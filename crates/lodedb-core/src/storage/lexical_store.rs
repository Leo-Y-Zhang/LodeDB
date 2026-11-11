use crate::storage::tvvf_store::read_exact_at;
use crate::storage::util::{
    body_sha256, checksummed_body_from_text, checksummed_body_payload, corrupt, get_i64, get_str,
    parse_json, read_json, read_text, sha256_bytes_hex, sha256_file_hex, sidecar_base_block,
    validate_sidecar_manifest, value_object, write_pretty_json_atomic, write_py_json, CoreResult,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const LEXICAL_INDEX_DELTA_DIR_SUFFIX: &str = ".tvlex-delta";

/// Delta segments [`open_held`] keeps open. Writers fold the journal before it
/// passes this many segments (`MAX_GENERATION_DELTA_SEGMENTS`), so a committed
/// store holds at most one descriptor for the base plus this many; segments
/// past it (a store outside that bound) keep their text in memory, as before.
const HELD_SEGMENT_LIMIT: usize = 64;
pub const LEXICAL_INDEX_MANIFEST_NAME: &str = "manifest.json";
pub const LEXICAL_INDEX_SCHEMA_VERSION: i64 = 1;

pub type TokenLists = Vec<Vec<String>>;

pub fn manifest_path(base_path: &Path) -> PathBuf {
    base_path
        .with_file_name(format!(
            "{}{}",
            base_path.file_name().unwrap().to_string_lossy(),
            LEXICAL_INDEX_DELTA_DIR_SUFFIX
        ))
        .join(LEXICAL_INDEX_MANIFEST_NAME)
}

pub fn load(
    base_path: &Path,
    manifest: Option<&Value>,
) -> CoreResult<BTreeMap<String, TokenLists>> {
    match read_bytes(base_path, manifest)? {
        Some(bytes) => bytes.parse(),
        None => Ok(BTreeMap::new()),
    }
}

/// A committed lexical store, base and delta segments, checked against the
/// commit manifest but not parsed. A read-only open keeps this instead of the
/// token lists and parses it the first time something needs the tokens. From
/// [`open_held`] it holds open files rather than their text, so a handle that
/// never runs a lexical query never reads the text into memory; holding files
/// rather than paths keeps the parse working after a writer collects the epoch.
#[derive(Debug, Clone)]
pub struct LexicalBytes {
    base: LexicalSource,
    segments: Vec<LexicalSource>,
}

/// One committed file: its text, or an open handle with the length and
/// SHA-256 its contents had when the store was opened.
#[derive(Debug, Clone)]
enum LexicalSource {
    Text(String),
    Held {
        file: Arc<File>,
        len: u64,
        sha256: String,
        context: &'static str,
    },
}

/// Reads what [`load`] parses, with the same manifest, ordering and segment
/// checksum checks. `None` when the base file is absent.
pub fn read_bytes(base_path: &Path, manifest: Option<&Value>) -> CoreResult<Option<LexicalBytes>> {
    read_sources(base_path, manifest, 0)
}

/// [`read_bytes`] with the same checks (including that each file is UTF-8),
/// keeping the base and up to [`HELD_SEGMENT_LIMIT`] segments as open files
/// instead of text. The text is read again, and must hash the same, each time
/// the store is parsed.
pub fn open_held(base_path: &Path, manifest: Option<&Value>) -> CoreResult<Option<LexicalBytes>> {
    read_sources(base_path, manifest, HELD_SEGMENT_LIMIT)
}

/// `held_segments == 0` reads everything as text; otherwise the base and the
/// first `held_segments` segments are held open.
fn read_sources(
    base_path: &Path,
    manifest: Option<&Value>,
    held_segments: usize,
) -> CoreResult<Option<LexicalBytes>> {
    if !base_path.is_file() {
        return Ok(None);
    }
    if let Some(manifest) = manifest {
        validate_sidecar_manifest(
            base_path,
            manifest,
            LEXICAL_INDEX_SCHEMA_VERSION,
            "lexical index",
        )?;
    }
    let base = if held_segments == 0 {
        LexicalSource::Text(read_text(base_path, "lexical index base")?)
    } else {
        let base = LexicalSource::hold(base_path, "lexical index base")?;
        // The manifest check above read the path; the retained handle must
        // hold those same bytes.
        let expected = manifest
            .and_then(|manifest| manifest.get("base"))
            .and_then(Value::as_object)
            .map(|base| get_str(base, "sha256"))
            .unwrap_or_default();
        if !expected.is_empty() && base.held_sha256() != Some(expected) {
            return Err(corrupt("lexical index base failed manifest checksum"));
        }
        base
    };
    let mut segments = Vec::new();
    if let Some(manifest) = manifest {
        let manifest = value_object(manifest, "lexical index manifest")?;
        let delta_dir = base_path.with_file_name(format!(
            "{}{}",
            base_path.file_name().unwrap().to_string_lossy(),
            LEXICAL_INDEX_DELTA_DIR_SUFFIX
        ));
        let mut previous_seq = -1_i64;
        for entry in manifest
            .get("deltas")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let entry = value_object(entry, "lexical index delta manifest entry")?;
            let sequence = get_i64(entry, "seq", -1);
            if sequence <= previous_seq {
                return Err(corrupt("lexical index manifest has out-of-order segments"));
            }
            previous_seq = sequence;
            let file_name = get_str(entry, "file_name");
            let path = delta_dir.join(file_name);
            if file_name.is_empty() || !path.is_file() {
                return Err(corrupt(format!(
                    "lexical index segment is missing: {file_name}"
                )));
            }
            let checksum_failed = || {
                corrupt(format!(
                    "lexical index segment failed checksum: {file_name}"
                ))
            };
            if segments.len() < held_segments {
                let segment = LexicalSource::hold(&path, "lexical index segment")?;
                if segment.held_sha256() != Some(get_str(entry, "sha256")) {
                    return Err(checksum_failed());
                }
                segments.push(segment);
                continue;
            }
            if sha256_file_hex(&path)? != get_str(entry, "sha256") {
                return Err(checksum_failed());
            }
            segments.push(LexicalSource::Text(read_text(
                &path,
                "lexical index segment",
            )?));
        }
    }
    Ok(Some(LexicalBytes { base, segments }))
}

impl LexicalSource {
    /// Opens `path` and streams it once to record its length and SHA-256 and
    /// to check it is UTF-8, keeping only the handle.
    fn hold(path: &Path, context: &'static str) -> CoreResult<Self> {
        let read_error = |error: std::io::Error| {
            corrupt(format!("{} could not be read: {error}", path.display()))
        };
        let mut file = File::open(path).map_err(read_error)?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        let mut len = 0_u64;
        // The bytes not yet checked as UTF-8: the latest read, after at most
        // three bytes of a sequence split across the previous read.
        let mut pending = Vec::new();
        loop {
            let read = file.read(&mut buffer).map_err(read_error)?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
            len += read as u64;
            pending.extend_from_slice(&buffer[..read]);
            match std::str::from_utf8(&pending) {
                Ok(_) => pending.clear(),
                Err(error) if error.error_len().is_none() => {
                    pending.drain(..error.valid_up_to());
                }
                Err(_) => return Err(not_utf8(context)),
            }
        }
        if !pending.is_empty() {
            return Err(not_utf8(context));
        }
        Ok(Self::Held {
            file: Arc::new(file),
            len,
            sha256: format!("{:x}", digest.finalize()),
            context,
        })
    }

    fn held_sha256(&self) -> Option<&str> {
        match self {
            Self::Text(_) => None,
            Self::Held { sha256, .. } => Some(sha256),
        }
    }

    /// The text, read again from a held file. Fails closed, returning no
    /// text, if the file no longer holds the bytes it had at open.
    fn text(&self) -> CoreResult<Cow<'_, str>> {
        let (file, len, sha256, context) = match self {
            Self::Text(text) => return Ok(Cow::Borrowed(text)),
            Self::Held {
                file,
                len,
                sha256,
                context,
            } => (file, *len, sha256, *context),
        };
        let size =
            usize::try_from(len).map_err(|_| corrupt(format!("{context} is too large to read")))?;
        let mut bytes = vec![0_u8; size];
        read_exact_at(file, &mut bytes, 0)
            .map_err(|error| corrupt(format!("{context} could not be read: {error}")))?;
        if sha256_bytes_hex(&bytes) != *sha256 {
            return Err(corrupt(format!("{context} changed after it was opened")));
        }
        String::from_utf8(bytes)
            .map(Cow::Owned)
            .map_err(|_| not_utf8(context))
    }
}

fn not_utf8(context: &str) -> crate::error::CoreError {
    corrupt(format!(
        "{context} could not be read: stream did not contain valid UTF-8"
    ))
}

impl LexicalBytes {
    /// Visits the effective committed documents without a corpus-sized token
    /// tree. Slices resolve delta precedence first; each document is decoded
    /// once, sharing that decode between checksum validation and the builder.
    /// Callers must discard partial work on error. Visit order is unspecified.
    pub(crate) fn visit_documents(
        &self,
        mut visit: impl FnMut(&str, TokenLists),
    ) -> CoreResult<()> {
        let base = self.base.text()?;
        let segments = self
            .segments
            .iter()
            .map(LexicalSource::text)
            .collect::<CoreResult<Vec<_>>>()?;
        let mut frames = vec![DocumentFrame::parse(&base, "documents", false)?];
        for segment in &segments {
            frames.push(DocumentFrame::parse(segment, "upserted", true)?);
        }
        let mut effective = BTreeMap::new();
        for frame in &frames {
            for id in &frame.deleted {
                effective.remove(id.as_str());
            }
            for (id, raw) in &frame.documents {
                effective.insert(id.as_str(), *raw);
            }
        }
        for frame in &frames {
            frame.verify_and_visit(&effective, &mut visit)?;
        }
        Ok(())
    }

    /// Parses the base and replays the segments in manifest order.
    pub fn parse(&self) -> CoreResult<BTreeMap<String, TokenLists>> {
        let mut documents = parse_base(&self.base.text()?)?;
        for segment in &self.segments {
            let body = segment_body(&segment.text()?)?;
            for deleted in body
                .get("deleted")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                documents.remove(deleted);
            }
            if let Some(upserted) = body.get("upserted").and_then(Value::as_object) {
                for (document_id, tokens) in upserted {
                    documents.insert(document_id.clone(), normalize_token_lists(tokens)?);
                }
            }
        }
        Ok(documents)
    }
}

type DocumentSlices<'a> = BTreeMap<String, &'a serde_json::value::RawValue>;

/// A lexical frame retains only ids and borrowed JSON slices, never tokens.
/// Keeping key order here accepts noncanonical input while hashing exactly the
/// same canonical Python JSON as the eager loader (including unknown fields).
struct DocumentFrame<'a> {
    fields: DocumentSlices<'a>,
    documents: DocumentSlices<'a>,
    deleted: Vec<String>,
    expected_hash: String,
    collection: &'static str,
}

impl<'a> DocumentFrame<'a> {
    fn parse(text: &'a str, collection: &'static str, segment: bool) -> CoreResult<Self> {
        let parse_fields = |raw: &'a str| -> CoreResult<DocumentSlices<'a>> {
            serde_json::from_str(raw).map_err(|error| corrupt(format!("lexical index: {error}")))
        };
        let payload = parse_fields(text)?;
        let schema = payload
            .get("schema_version")
            .and_then(|raw| serde_json::from_str::<i64>(raw.get()).ok());
        if schema != Some(LEXICAL_INDEX_SCHEMA_VERSION) {
            return Err(corrupt("unsupported lexical index schema version"));
        }
        let body = payload
            .get("body")
            .ok_or_else(|| corrupt("lexical index body is missing"))?;
        let fields = parse_fields(body.get())?;
        let expected_hash = payload
            .get("body_sha256")
            .and_then(|raw| serde_json::from_str::<String>(raw.get()).ok())
            .unwrap_or_default();
        let documents = match fields.get(collection) {
            Some(raw) if raw.get().trim_start().starts_with('{') => parse_fields(raw.get())?,
            _ if segment => BTreeMap::new(),
            _ => return Err(corrupt("lexical index base documents must be an object")),
        };
        let deleted = if segment {
            fields
                .get("deleted")
                .map(|raw| parse_json(raw.get(), "lexical index deleted ids"))
                .transpose()?
                .as_ref()
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        } else {
            Vec::new()
        };
        Ok(Self {
            fields,
            documents,
            deleted,
            expected_hash,
            collection,
        })
    }

    fn verify_and_visit(
        &self,
        effective: &BTreeMap<&str, &serde_json::value::RawValue>,
        visit: &mut impl FnMut(&str, TokenLists),
    ) -> CoreResult<()> {
        use crate::storage::util::py_canonical_json;
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(b"{");
        for (offset, (key, raw)) in self.fields.iter().enumerate() {
            if offset > 0 {
                hasher.update(b", ");
            }
            hasher.update(py_canonical_json(&Value::String(key.clone()))?.as_bytes());
            hasher.update(b": ");
            if key == self.collection && raw.get().trim_start().starts_with('{') {
                hasher.update(b"{");
                for (offset, (id, tokens)) in self.documents.iter().enumerate() {
                    if offset > 0 {
                        hasher.update(b", ");
                    }
                    hasher.update(py_canonical_json(&Value::String(id.clone()))?.as_bytes());
                    hasher.update(b": ");
                    let value = parse_json(tokens.get(), "lexical index token lists")?;
                    hasher.update(py_canonical_json(&value)?.as_bytes());
                    // Validate even entries later replaced/deleted, as the eager
                    // loader does, but build only the final version of a unit.
                    let lists = normalize_token_lists(&value)?;
                    if effective
                        .get(id.as_str())
                        .is_some_and(|current| std::ptr::eq(*current, *tokens))
                    {
                        visit(id, lists);
                    }
                }
                hasher.update(b"}");
            } else {
                let value = parse_json(raw.get(), "lexical index body field")?;
                hasher.update(py_canonical_json(&value)?.as_bytes());
            }
        }
        hasher.update(b"}");
        if format!("{:x}", hasher.finalize()) != self.expected_hash {
            return Err(corrupt("lexical index failed checksum"));
        }
        Ok(())
    }
}
fn parse_base(text: &str) -> CoreResult<BTreeMap<String, TokenLists>> {
    let body = checksummed_body_from_text(text, LEXICAL_INDEX_SCHEMA_VERSION, "lexical index")?;
    let body_object = value_object(&body, "lexical index base body")?;
    let documents = body_object
        .get("documents")
        .and_then(Value::as_object)
        .ok_or_else(|| corrupt("lexical index base documents must be an object"))?;
    documents
        .iter()
        .map(|(key, value)| Ok((key.clone(), normalize_token_lists(value)?)))
        .collect()
}

pub fn record_base(
    base_path: &Path,
    documents: &BTreeMap<String, TokenLists>,
    fsync: bool,
) -> CoreResult<Value> {
    let body = serde_json::json!({
        "schema_version": LEXICAL_INDEX_SCHEMA_VERSION,
        "documents": documents,
    });
    let payload = checksummed_body_payload(LEXICAL_INDEX_SCHEMA_VERSION, body)?;
    write_py_json(base_path, &payload, fsync)?;
    let manifest_path = manifest_path(base_path);
    let previous = if manifest_path.is_file() {
        Some(read_json(&manifest_path, "lexical index manifest")?)
    } else {
        None
    };
    let next_seq = previous
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|object| object.get("next_seq"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
        + 1;
    if let Some(parent) = manifest_path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            corrupt(format!(
                "lexical index delta directory could not be created: {error}"
            ))
        })?;
    }
    let manifest = serde_json::json!({
        "schema_version": LEXICAL_INDEX_SCHEMA_VERSION,
        "base": sidecar_base_block(
            base_path,
            "lexical index",
            [("document_count", Value::from(documents.len()))],
        )?,
        "deltas": [],
        "next_seq": next_seq,
    });
    write_pretty_json_atomic(&manifest_path, &manifest, fsync)?;
    Ok(manifest)
}

pub fn append_delta(
    base_path: &Path,
    upserted: &BTreeMap<String, TokenLists>,
    deleted: &[String],
    document_count_after: usize,
    fsync: bool,
) -> CoreResult<Value> {
    let manifest_path = manifest_path(base_path);
    let mut manifest = read_json(&manifest_path, "lexical index manifest")?;
    let manifest_object = manifest
        .as_object_mut()
        .ok_or_else(|| corrupt("lexical index manifest must be a JSON object"))?;
    let sequence = manifest_object
        .get("next_seq")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let body = serde_json::json!({
        "schema_version": LEXICAL_INDEX_SCHEMA_VERSION,
        "upserted": upserted,
        "deleted": deleted,
    });
    let segment = serde_json::json!({
        "schema_version": LEXICAL_INDEX_SCHEMA_VERSION,
        "seq": sequence,
        "document_count_after": document_count_after,
        "body_sha256": body_sha256(&body)?,
        "body": body,
    });
    let segment_name = format!("lexical-{sequence:08}.lxd");
    let delta_dir = base_path.with_file_name(format!(
        "{}{}",
        base_path.file_name().unwrap().to_string_lossy(),
        LEXICAL_INDEX_DELTA_DIR_SUFFIX
    ));
    let segment_path = delta_dir.join(&segment_name);
    write_py_json(&segment_path, &segment, fsync)?;
    let deltas = manifest_object
        .entry("deltas")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| corrupt("lexical index manifest deltas must be a list"))?;
    deltas.push(serde_json::json!({
        "file_name": segment_name,
        "sha256": sha256_file_hex(&segment_path)?,
        "file_bytes": segment_path.metadata().map_err(|error| corrupt(format!("lexical index segment metadata failed: {error}")))?.len(),
        "seq": sequence,
        "upserted": upserted.len(),
        "deleted": deleted.len(),
    }));
    manifest_object.insert("next_seq".to_string(), Value::from(sequence + 1));
    write_pretty_json_atomic(&manifest_path, &manifest, fsync)?;
    Ok(manifest)
}

fn segment_body(text: &str) -> CoreResult<Value> {
    let segment = parse_json(text, "lexical index segment")?;
    let segment = value_object(&segment, "lexical index segment")?;
    if get_i64(segment, "schema_version", -1) != LEXICAL_INDEX_SCHEMA_VERSION {
        return Err(corrupt("unsupported lexical index segment schema version"));
    }
    let body = segment
        .get("body")
        .ok_or_else(|| corrupt("lexical index segment body is missing"))?;
    if !body.is_object() {
        return Err(corrupt("lexical index segment body is missing"));
    }
    if body_sha256(body)? != get_str(segment, "body_sha256") {
        return Err(corrupt("lexical index segment failed checksum"));
    }
    Ok(body.clone())
}

fn normalize_token_lists(value: &Value) -> CoreResult<TokenLists> {
    let chunks = value
        .as_array()
        .ok_or_else(|| corrupt("lexical index token lists must be a list of chunks"))?;
    chunks
        .iter()
        .map(|chunk| {
            let tokens = chunk
                .as_array()
                .ok_or_else(|| corrupt("lexical index chunk must be a list of tokens"))?;
            Ok(tokens
                .iter()
                .map(|token| token.as_str().unwrap_or("").to_string())
                .collect())
        })
        .collect()
}

#[cfg(test)]
impl LexicalBytes {
    pub(crate) fn from_text(base: String, segments: Vec<String>) -> Self {
        Self {
            base: LexicalSource::Text(base),
            segments: segments.into_iter().map(LexicalSource::Text).collect(),
        }
    }

    /// Text bytes kept in memory, and files kept open.
    pub(crate) fn residency(&self) -> (usize, usize) {
        let (mut text, mut files) = (0, 0);
        for source in std::iter::once(&self.base).chain(&self.segments) {
            match source {
                LexicalSource::Text(bytes) => text += bytes.len(),
                LexicalSource::Held { .. } => files += 1,
            }
        }
        (text, files)
    }
}

#[cfg(test)]
mod streaming_tests {
    use super::*;
    use crate::storage::util::{checksummed_body_payload, py_canonical_json};
    use serde_json::json;

    fn bytes(body: Value) -> String {
        // Pretty output exercises whitespace, non-ASCII and escaped keys;
        // checksums still use the canonical Python encoding.
        serde_json::to_string_pretty(&checksummed_body_payload(1, body).unwrap()).unwrap()
    }

    #[test]
    fn document_visitor_matches_eager_parse_with_deltas_and_escapes() {
        let base = bytes(json!({"schema_version": 1, "documents": {
            "z": [["old"]], "a\\\"é": [["café", "😀", "", 9]], "empty": [], "chunks": [[], ["alpha"]]
        }}));
        let segments = vec![
            bytes(
                json!({"schema_version": 1, "deleted": ["z", "missing"], "upserted": {"chunks": [["new"]], "z": [["restored"]]}}),
            ),
            bytes(json!({"schema_version": 1, "deleted": ["z"], "upserted": {"final": [[]]}})),
        ];
        let lexical = LexicalBytes::from_text(base.clone(), segments.clone());
        let mut visited = BTreeMap::new();
        lexical
            .visit_documents(|id, lists| {
                visited.insert(id.to_string(), lists);
            })
            .unwrap();
        assert_eq!(visited, lexical.parse().unwrap());
        // Also accept compact canonical input, not just pretty JSON.
        let lexical = LexicalBytes::from_text(
            py_canonical_json(&serde_json::from_str::<Value>(&base).unwrap()).unwrap(),
            segments,
        );
        let mut canonical = BTreeMap::new();
        lexical
            .visit_documents(|id, lists| {
                canonical.insert(id.to_string(), lists);
            })
            .unwrap();
        assert_eq!(canonical, visited);
    }

    #[test]
    fn document_visitor_rejects_corruption_and_invalid_replaced_entries() {
        let good = bytes(json!({"schema_version": 1, "documents": {"d": [["alpha"]]}}));
        let bad_tokens = bytes(json!({"schema_version": 1, "documents": {"d": ["not a chunk"]}}));
        let bad_documents = bytes(json!({"schema_version": 1, "documents": []}));
        let bad_schema = good.replacen("\"schema_version\": 1", "\"schema_version\": 2", 2);
        for base in [
            good.replace("alpha", "beta"),
            bad_tokens,
            bad_documents,
            bad_schema,
        ] {
            let lexical = LexicalBytes::from_text(
                base,
                vec![bytes(
                    json!({"schema_version": 1, "deleted": ["d"], "upserted": {}}),
                )],
            );
            assert!(lexical.parse().is_err());
            assert!(lexical.visit_documents(|_, _| {}).is_err());
        }
        let lexical = LexicalBytes::from_text(
            good,
            vec![
                bytes(json!({"schema_version": 1, "upserted": {"d": [["alpha"]]}}))
                    .replace("alpha", "beta"),
            ],
        );
        assert!(lexical.visit_documents(|_, _| {}).is_err());
    }

    /// A committed store on disk: base, `segments` deltas and the manifest
    /// describing them, as a writer commits it.
    fn write_store(name: &str, segments: usize) -> (PathBuf, Value) {
        let dir =
            std::env::temp_dir().join(format!("lodedb-lexical-held-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let base_path = dir.join("g0.tvlex");
        fs::write(
            &base_path,
            bytes(json!({"schema_version": 1, "documents": {
                "a": [["alpha", "é"]], "b": [["beta"]], "c": [["gamma"]]
            }})),
        )
        .unwrap();
        let delta_dir = manifest_path(&base_path).parent().unwrap().to_path_buf();
        fs::create_dir_all(&delta_dir).unwrap();
        let mut deltas = Vec::new();
        for seq in 0..segments {
            let file_name = format!("{seq:06}.json");
            let path = delta_dir.join(&file_name);
            fs::write(
                &path,
                bytes(json!({"schema_version": 1, "deleted": ["b"],
                    "upserted": {format!("d{seq}"): [[format!("delta{seq}")]], "a": [["alpha", format!("v{seq}")]]}})),
            )
            .unwrap();
            deltas.push(json!({"seq": seq, "file_name": file_name,
                "sha256": sha256_file_hex(&path).unwrap()}));
        }
        let manifest = json!({"schema_version": LEXICAL_INDEX_SCHEMA_VERSION,
            "base": {"sha256": sha256_file_hex(&base_path).unwrap()}, "deltas": deltas});
        (base_path, manifest)
    }

    fn visited(lexical: &LexicalBytes) -> BTreeMap<String, TokenLists> {
        let mut out = BTreeMap::new();
        lexical
            .visit_documents(|id, lists| {
                out.insert(id.to_string(), lists);
            })
            .unwrap();
        out
    }

    #[test]
    fn held_files_retain_no_text_and_parse_like_read_text() {
        let (base_path, manifest) = write_store("parse", 3);
        let read = read_bytes(&base_path, Some(&manifest)).unwrap().unwrap();
        let held = open_held(&base_path, Some(&manifest)).unwrap().unwrap();
        assert_eq!(read.residency().1, 0);
        assert_eq!(held.residency(), (0, 4));
        assert_eq!(held.parse().unwrap(), read.parse().unwrap());
        assert_eq!(visited(&held), visited(&read));
        // Parsing twice reads the files twice and agrees; nothing is kept.
        assert_eq!(held.parse().unwrap(), read.parse().unwrap());
        assert_eq!(held.residency(), (0, 4));
        // The hash streamed at open is the whole-file hash the manifest uses.
        assert_eq!(
            held.base.held_sha256(),
            Some(sha256_file_hex(&base_path).unwrap().as_str())
        );
        fs::remove_dir_all(base_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn segments_past_the_held_limit_keep_their_text() {
        let (base_path, manifest) = write_store("limit", 3);
        let read = read_bytes(&base_path, Some(&manifest)).unwrap().unwrap();
        // Exactly at the limit every segment is held; one above, the last
        // segment falls back to text.
        let at_limit = read_sources(&base_path, Some(&manifest), 3)
            .unwrap()
            .unwrap();
        assert_eq!(at_limit.residency(), (0, 4));
        let below = read_sources(&base_path, Some(&manifest), 2)
            .unwrap()
            .unwrap();
        let last = manifest_path(&base_path).with_file_name("000002.json");
        assert_eq!(
            below.residency(),
            (fs::metadata(last).unwrap().len() as usize, 3)
        );
        assert_eq!(at_limit.parse().unwrap(), read.parse().unwrap());
        assert_eq!(below.parse().unwrap(), read.parse().unwrap());
        fs::remove_dir_all(base_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn held_open_keeps_the_manifest_errors() {
        let (base_path, manifest) = write_store("errors", 2);
        let message = |manifest: &Value| {
            open_held(&base_path, Some(manifest))
                .unwrap_err()
                .to_string()
        };
        let mut swapped = manifest.clone();
        swapped["deltas"][1]["seq"] = json!(0);
        assert!(message(&swapped).contains("out-of-order segments"));
        let mut missing = manifest.clone();
        missing["deltas"][1]["file_name"] = json!("absent.json");
        assert!(message(&missing).contains("lexical index segment is missing: absent.json"));
        let mut checksum = manifest.clone();
        checksum["deltas"][0]["sha256"] = json!("0".repeat(64));
        assert!(message(&checksum).contains("lexical index segment failed checksum: 000000.json"));
        let mut base = manifest.clone();
        base["base"]["sha256"] = json!("0".repeat(64));
        assert!(message(&base).contains("lexical index base failed manifest checksum"));
        fs::remove_dir_all(base_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn held_files_reject_bytes_that_change_after_open_or_are_not_utf8() {
        let (base_path, manifest) = write_store("tamper", 1);
        let held = open_held(&base_path, Some(&manifest)).unwrap().unwrap();
        let original = fs::read(&base_path).unwrap();
        let tampered = String::from_utf8(original.clone())
            .unwrap()
            .replace("gamma", "delta");
        assert_eq!(tampered.len(), original.len());
        fs::write(&base_path, &tampered).unwrap();
        let error = held.parse().unwrap_err();
        assert_eq!(error.code(), crate::error::CoreErrorCode::CorruptStore);
        assert!(error.to_string().contains("changed after it was opened"));
        assert!(held.visit_documents(|_, _| {}).is_err());
        // Nothing was cached: restoring the bytes makes the same handle work.
        fs::write(&base_path, &original).unwrap();
        assert!(held.parse().is_ok());

        // A split multi-byte sequence across reads is fine; invalid UTF-8 is
        // refused at open, as reading the text was.
        let mut invalid = original.clone();
        let at = invalid.iter().position(|byte| *byte == b'g').unwrap();
        invalid[at] = 0xff;
        fs::write(&base_path, &invalid).unwrap();
        let error = open_held(&base_path, None).unwrap_err();
        assert!(error.to_string().contains("not contain valid UTF-8"));
        assert!(read_bytes(&base_path, None).is_err());
        let long = format!("{}é", "x".repeat(64 * 1024 - 1));
        fs::write(&base_path, &long).unwrap();
        let held = open_held(&base_path, None).unwrap().unwrap();
        assert_eq!(held.base.text().unwrap(), long);
        fs::remove_dir_all(base_path.parent().unwrap()).unwrap();
    }
}
