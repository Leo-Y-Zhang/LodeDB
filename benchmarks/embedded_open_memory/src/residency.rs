//! Optional clean-process residency samples; never enabled in the default probe.
use std::sync::atomic::{AtomicBool, Ordering};

pub static ENABLED: AtomicBool = AtomicBool::new(false);

pub fn report(stage: &str) {
    // Capture before reading procfs or formatting the report.
    let heap = crate::LIVE.load(Ordering::Relaxed);
    let heap_peak = crate::PEAK.load(Ordering::Relaxed);
    let (current, lifetime_peak) = crate::footprint();
    let mut row = serde_json::json!({
        "kind": "residency", "stage": stage, "heap": heap, "heap_peak": heap_peak,
        "process_current": current, "process_lifetime_peak": lifetime_peak,
        "smaps": null,
    });
    #[cfg(target_os = "linux")]
    {
        let rollup = std::fs::read_to_string("/proc/self/smaps_rollup")
            .expect("read smaps_rollup for --residency");
        let rss = field(&rollup, "Rss:");
        let dirty = field(&rollup, "Private_Dirty:");
        let swap = field(&rollup, "Swap:");
        let anonymous = field(&rollup, "Anonymous:");
        row["smaps"] = serde_json::json!({
            "rss": rss, "pss": field(&rollup, "Pss:"),
            "private_dirty": dirty, "private_clean": field(&rollup, "Private_Clean:"),
            "anonymous": anonymous, "file_shared": rss.saturating_sub(anonymous),
            "swap": swap, "private_dirty_plus_swap_analogue": dirty + swap,
            "non_heap_plus_allocator_slack": rss as i64 - heap as i64,
            "largest_mappings": mappings(&std::fs::read_to_string("/proc/self/smaps")
                .expect("read smaps for --residency")),
        });
    }
    println!("{row}");
}

#[cfg(target_os = "linux")]
fn field(text: &str, key: &str) -> u64 {
    text.lines()
        .find_map(|line| {
            line.strip_prefix(key)?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        })
        .expect("required smaps field")
        * 1024
}

/// Resident bytes per mapping kind, largest first. Kinds are a fixed vocabulary
/// so store paths (mapped sidecars) never reach the output.
#[cfg(target_os = "linux")]
fn mappings(text: &str) -> Vec<serde_json::Value> {
    let mut totals: Vec<(&str, u64)> = Vec::new();
    let mut label = "";
    for line in text.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        if words.len() >= 5 && words[0].contains('-') {
            label = if line.contains("embedded-open-memory") {
                "probe binary"
            } else if line.contains("openblas") {
                "OpenBLAS library"
            } else if line.contains("[stack") {
                "stack"
            } else if line.contains("[heap]") {
                "heap arena"
            } else if line.contains(".so") || line.contains("ld-linux") {
                "other shared library"
            } else if words.len() > 5 {
                "other file or kernel mapping"
            } else {
                "anonymous (may include allocator/BLAS buffers)"
            };
        } else if line.starts_with("Rss:") {
            let rss = words[1].parse::<u64>().expect("mapping RSS") * 1024;
            match totals.iter_mut().find(|(name, _)| *name == label) {
                Some((_, total)) => *total += rss,
                None => totals.push((label, rss)),
            }
        }
    }
    totals.retain(|&(_, rss)| rss > 0);
    totals.sort_by_key(|&(_, rss)| std::cmp::Reverse(rss));
    totals
        .into_iter()
        .map(|(mapping, rss)| serde_json::json!({"mapping": mapping, "rss": rss}))
        .collect()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn parses_kib_sums_kinds_and_redacts_mapping_paths() {
        let sample = "0001-0002 r-xp 0 00:00 1 /private/store/secret.tvim\nRss: 12 kB\n\
            Anonymous: 4 kB\n0002-0003 r-xp 0 00:00 2 /lib/libopenblas.so\nRss: 8 kB\n\
            0003-0004 rw-p 0 00:00 0\nRss: 3 kB\n0004-0005 rw-p 0 00:00 0\nRss: 6 kB\n\
            0005-0006 rw-p 0 00:00 0 [stack]\nRss: 0 kB\n";
        assert_eq!(field(sample, "Anonymous:"), 4096);
        let rows = mappings(sample);
        assert_eq!(rows.len(), 3, "empty kinds are dropped");
        assert_eq!(rows[0]["rss"], 12288);
        assert_eq!(rows[1]["rss"], 9216, "anonymous mappings are summed");
        assert_eq!(rows[2]["mapping"], "OpenBLAS library");
        assert!(!serde_json::to_string(&rows).unwrap().contains("secret"));
    }
}
