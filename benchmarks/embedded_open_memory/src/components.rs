//! Exact allocation-site accounting. Bookkeeping and symbolization use System
//! under a thread-local recursion guard and never enter the measured counters.
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

const LABELS: [&str; 9] = [
    "lexical source text",
    "vectors",
    "ANN sidecar",
    "text store",
    "document state/metadata: JSON",
    "document state/metadata: maps",
    "BM25 serving index",
    "core other",
    "runtime other",
];
// Walk from the allocating frame toward its callers. Generic helpers (including
// serde_json) defer to their caller's subsystem. A prefix matches the head of a
// symbol's path (`lodedb_core::..` or `<lodedb_core::..`), never a generic
// argument such as `<Vec<lodedb_core::vector::..>>::push`. Keep this table in
// sync with README.
const PREFIXES: &[(&str, usize)] = &[
    ("lodedb_core::storage::lexical_store::", 0),
    ("lodedb_core::engine::DeferredTokenLists", 0),
    ("lodedb_core::storage::tvvf_store::", 1),
    ("lodedb_core::storage::tvim_delta::", 1),
    ("lodedb_core::storage::multivec_store::", 1),
    ("lodedb_core::vector::", 1),
    ("turbovec::", 1),
    ("lodedb_core::storage::tvann_store::", 2),
    ("lodedb_core::storage::text_store::", 3),
    ("lodedb_core::storage::state_journal::", 4),
    ("lodedb_core::storage::legacy::", 4),
    ("lodedb_core::engine::index_from_loaded_store", 5),
    ("lodedb_core::lexical::bm25::", 6),
];
const CORE_OTHER: usize = LABELS.len() - 2;
const RUNTIME: usize = LABELS.len() - 1;
type Counts = [usize; LABELS.len()];
static ENABLED: AtomicBool = AtomicBool::new(false);
static TRACKER: OnceLock<Mutex<Tracker>> = OnceLock::new();
thread_local! { static INTERNAL: Cell<bool> = const { Cell::new(false) }; }

pub fn internal() -> bool {
    INTERNAL.try_with(Cell::get).unwrap_or(true)
}

struct Guard;
impl Guard {
    fn enter() -> Self {
        INTERNAL.with(|cell| assert!(!cell.replace(true)));
        Self
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        INTERNAL.with(|cell| cell.set(false));
    }
}

#[derive(Default)]
struct Tracker {
    blocks: HashMap<usize, (usize, usize)>, // address -> (requested bytes, component)
    sites: HashMap<Vec<usize>, usize>,
    live: Counts,
    peak: Counts, // simultaneous stage peak, not a sum of component maxima
    global_peak: Counts,
    maxima: Counts, // individual high-water marks; deliberately not additive
}

fn classify(names: impl IntoIterator<Item = String>) -> usize {
    let mut fallback = RUNTIME;
    for name in names {
        let path = name.strip_prefix('<').unwrap_or(&name);
        for &(prefix, bucket) in PREFIXES {
            if path.starts_with(prefix) {
                return bucket;
            }
        }
        if path.starts_with("lodedb_core::") {
            fallback = CORE_OTHER;
        }
    }
    fallback
}

impl Tracker {
    fn site(&mut self) -> usize {
        let mut frames = Vec::new();
        backtrace::trace(|frame| {
            frames.push(frame.clone());
            true
        });
        let key: Vec<_> = frames.iter().map(|frame| frame.ip() as usize).collect();
        if let Some(&bucket) = self.sites.get(&key) {
            return bucket;
        }
        let mut names = Vec::new();
        for frame in &frames {
            backtrace::resolve_frame(frame, |symbol| {
                // `{:#}` drops the crate hashes v0 mangling puts in each path.
                if let Some(name) = symbol.name() {
                    names.push(format!("{name:#}"));
                }
            });
        }
        let bucket = classify(names);
        self.sites.insert(key, bucket);
        bucket
    }

    fn update_peak(&mut self) {
        if self.live.iter().sum::<usize>() > self.peak.iter().sum() {
            self.peak = self.live;
        }
        if self.live.iter().sum::<usize>() > self.global_peak.iter().sum() {
            self.global_peak = self.live;
        }
        for (max, live) in self.maxima.iter_mut().zip(self.live) {
            *max = (*max).max(live);
        }
    }

    fn remove(&mut self, ptr: *mut u8, size: usize) -> usize {
        let (recorded, bucket) = self
            .blocks
            .remove(&(ptr as usize))
            .unwrap_or((size, RUNTIME));
        assert_eq!(recorded, size);
        self.live[bucket] -= size;
        bucket
    }
}

fn with_tracker(f: impl FnOnce(&mut Tracker)) {
    if ENABLED.load(Ordering::Relaxed) {
        let _guard = Guard::enter();
        f(&mut TRACKER.get().unwrap().lock().unwrap());
    }
}

pub fn enable() {
    let _guard = Guard::enter();
    let mut tracker = Tracker::default();
    // Pre-main runtime allocations have no recorded stack; retain their exact
    // byte count in runtime other, including any later frees/reallocations.
    tracker.live[RUNTIME] = crate::LIVE.load(Ordering::Relaxed);
    tracker.update_peak();
    assert!(TRACKER.set(Mutex::new(tracker)).is_ok());
    ENABLED.store(true, Ordering::Relaxed);
}

pub fn allocated(ptr: *mut u8, size: usize) {
    with_tracker(|tracker| {
        let bucket = tracker.site();
        tracker.blocks.insert(ptr as usize, (size, bucket));
        tracker.live[bucket] += size;
        tracker.update_peak();
    });
}

pub fn freed(ptr: *mut u8, size: usize) {
    with_tracker(|tracker| {
        tracker.remove(ptr, size);
    });
}

pub fn resized(old: *mut u8, new: *mut u8, old_size: usize, size: usize) {
    with_tracker(|tracker| {
        // A realloc retains its original allocation site, just as dhat does.
        let bucket = tracker.remove(old, old_size);
        tracker.blocks.insert(new as usize, (size, bucket));
        tracker.live[bucket] += size;
        tracker.update_peak();
    });
}

pub fn start_stage() {
    with_tracker(|tracker| tracker.peak = tracker.live);
}

pub fn report(stage: &str) -> bool {
    with_tracker(|tracker| {
        // Stages end with no allocation in flight, so live bytes must agree
        // exactly. Rayon workers can interleave the counter's and the tracker's
        // peak updates differently, so the peak is reported for report.py to
        // compare instead.
        let live = crate::LIVE.load(Ordering::Relaxed);
        assert_eq!(tracker.live.iter().sum::<usize>(), live);
        println!(
            "{}",
            serde_json::json!({
                "kind": "components", "stage": stage, "labels": LABELS,
                "live": tracker.live, "peak": tracker.peak,
                "global_peak": tracker.global_peak, "component_max": tracker.maxima,
                "heap": live, "heap_peak": tracker.peak.iter().sum::<usize>(),
                "counter_peak": crate::PEAK.load(Ordering::Relaxed),
            })
        );
    });
    ENABLED.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_subsystem_beats_generic_helpers_and_engine_caller() {
        let bucket = classify([
            "serde_json::de::parse".into(),
            "lodedb_core::storage::lexical_store::read_bytes".into(),
            "lodedb_core::engine::index_from_loaded_store".into(),
        ]);
        assert_eq!(bucket, 0);
        assert_eq!(classify(["lodedb_core::lexical::bm25::add".into()]), 6);
        assert_eq!(classify(["lodedb_core::engine::search".into()]), CORE_OTHER);
        assert_eq!(classify(["std::io::read".into()]), RUNTIME);
    }

    #[test]
    fn impl_paths_match_but_generic_arguments_do_not() {
        // Symbols as demangled with `{:#}` (v0 mangling, hashes hidden): the
        // type in `<Vec<..>>::push` is not where the allocation was made.
        let bucket = classify([
            "<alloc::vec::Vec<lodedb_core::vector::Code>>::push".into(),
            "<lodedb_core::storage::lexical_store::LexicalBytes>::parse".into(),
        ]);
        assert_eq!(bucket, 0);
        assert_eq!(
            classify(["<lodedb_core::storage::tvvf_store::TvvfReader as Clone>::clone".into()]),
            1
        );
        assert_eq!(
            classify(["core::ptr::drop_in_place::<lodedb_core::lexical::bm25::Bm25Index>".into()]),
            RUNTIME
        );
    }

    #[test]
    fn peak_is_simultaneous_and_preserves_freed_allocations() {
        let mut tracker = Tracker::default();
        tracker.live[0] = 100;
        tracker.update_peak();
        tracker.live[0] = 0;
        tracker.live[1] = 80;
        tracker.update_peak();
        assert_eq!(tracker.peak[0], 100);
        assert_eq!(tracker.peak[1], 0);
        assert_eq!(tracker.live.iter().sum::<usize>(), 80);
        assert_eq!(tracker.maxima[1], 80);
    }
}
