#!/usr/bin/env python3
"""Combine exact heap snapshots with medians from separate clean processes."""

import argparse
import json
import statistics
import subprocess

MIB = 1024 * 1024
STAGES = ("open", "search1", "settled")
SMAPS = (
    "rss",
    "pss",
    "private_dirty",
    "private_clean",
    "anonymous",
    "file_shared",
    "swap",
    "private_dirty_plus_swap_analogue",
    "non_heap_plus_allocator_slack",
)


def probe(binary, store, mode, flag):
    args = [binary, flag, "--no-refresh"]
    args += ["--control"] if mode == "control" else [store, "--mode", mode]
    output = subprocess.run(args, check=True, capture_output=True, text=True).stdout
    rows = (json.loads(line) for line in output.splitlines() if line.startswith("{"))
    return {row["stage"]: row for row in rows}


def close(a, b, floor=4096):
    """Within 1%, with a small floor for the near-empty control process."""
    return abs(a - b) <= max(floor, 0.01 * max(a, b))


def validate(mode, rows):
    for stage, row in rows.items():
        # The probe asserts live == counter itself; the peak is checked here
        # because rayon workers may order the two peak updates differently.
        assert sum(row["live"]) == row["heap"], f"{mode}/{stage}: live sum"
        assert sum(row["peak"]) == row["heap_peak"], f"{mode}/{stage}: peak sum"
        if not close(row["heap_peak"], row["counter_peak"]):
            raise SystemExit(f"{mode}/{stage}: component peak differs from the counter")


def spread(mode, first, repeat):
    """Live splits must repeat exactly; returns how far the peak splits moved.

    Peaks can move by a few KiB between runs (seen: one BM25 transient, 5.7 KiB
    in one of eight lexical runs), so they get a 64 KiB bound instead.
    """
    moved = 0
    for stage, row in first.items():
        if row["live"] != repeat[stage]["live"]:
            raise SystemExit(f"{mode}/{stage}: live split differs across runs")
        for key in ("peak", "global_peak"):
            for a, b in zip(row[key], repeat[stage][key], strict=True):
                moved = max(moved, abs(a - b))
    if moved > 64 * 1024:
        raise SystemExit(f"{mode}: peak split moved {moved} bytes across runs")
    return moved


def median(samples, stage, key, smaps=False):
    values = (row[stage]["smaps"][key] if smaps else row[stage][key] for row in samples)
    return statistics.median(values) / MIB


def show(clean, attributed, runs, store, mode):
    samples = [probe(clean, store, mode, "--residency") for _ in range(runs)]
    repeats = max(2, runs)
    heap = probe(attributed, store, mode, "--components")
    validate(mode, heap)
    moved = 0
    for _ in range(repeats - 1):
        repeat = probe(attributed, store, mode, "--components")
        validate(mode, repeat)
        moved = max(moved, spread(mode, heap, repeat))
    # The attributed process must see the same heap as the uninstrumented one.
    for stage in STAGES:
        for row in samples:
            for key in ("heap", "heap_peak"):
                if not close(heap[stage][key], row[stage][key]):
                    raise SystemExit(f"{mode}/{stage}: attributed {key} differs from clean")

    labels = heap["open"]["labels"]
    print(
        f"\n== {mode} (live split identical across {repeats} runs, peak split within"
        f" {moved / 1024:.1f} KiB; RSS median of {runs})"
    )
    print("Live heap by component, MiB. Peaks are the whole split at the stage's")
    print("highest total, not per-component maxima; share is of the settled heap.")
    print("| component | open peak | open done | first query peak | settled | share |")
    print("|---|---:|---:|---:|---:|---:|")
    columns = [
        heap["open"]["peak"],
        heap["open"]["live"],
        heap["search1"]["peak"],
        heap["settled"]["live"],
    ]
    settled = max(1, heap["settled"]["heap"])
    for i, label in enumerate(labels):
        cells = " | ".join(f"{column[i] / MIB:.2f}" for column in columns)
        print(f"| {label} | {cells} | {100 * columns[-1][i] / settled:.1f}% |")
    totals = [
        heap["open"]["heap_peak"],
        heap["open"]["heap"],
        heap["search1"]["heap_peak"],
        heap["settled"]["heap"],
    ]
    print("| live heap total | " + " | ".join(f"{v / MIB:.2f}" for v in totals) + " | 100% |")
    state = labels.index("document state/metadata: JSON")
    print(
        "State JSON's own high-water mark during open (not additive): "
        f"{heap['open']['component_max'][state] / MIB:.2f} MiB"
    )

    print("\nUninstrumented process, MiB (median; Linux RSS is not phys_footprint):")
    linux = samples[0]["open"]["smaps"] is not None
    print(
        "| stage | RSS | lifetime peak | PSS | Private_Dirty | Private_Clean | anonymous"
        " | file-backed | swap | Private_Dirty+swap (footprint analogue)"
        " | RSS - live heap (non-heap + allocator slack) | live heap | heap peak |"
    )
    print("|---|" + "---:|" * 12)
    for stage in STAGES:
        cells = [
            median(samples, stage, "process_current"),
            median(samples, stage, "process_lifetime_peak"),
        ]
        cells = [f"{value:.1f}" for value in cells]
        cells += [
            f"{median(samples, stage, key, True):.1f}" if linux else "n/a" for key in SMAPS[1:]
        ]
        cells += [f"{median(samples, stage, key):.1f}" for key in ("heap", "heap_peak")]
        print(f"| {stage} | " + " | ".join(cells) + " |")
    for stage in STAGES if linux else ():
        # Mappings come from the median-RSS run, not a mix of unrelated medians.
        ordered = sorted(samples, key=lambda row, stage=stage: row[stage]["smaps"]["rss"])
        maps = ordered[len(ordered) // 2][stage]["smaps"]["largest_mappings"]
        print(
            f"Resident mappings at {stage}: "
            + "; ".join(f"{row['mapping']} {row['rss'] / MIB:.1f}" for row in maps)
        )
    if not linux:
        print("smaps rows and mappings: n/a; process columns above are macOS phys_footprint.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--clean", required=True)
    parser.add_argument("--attributed", required=True)
    parser.add_argument("stores", nargs="+")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    print("\nNo store (process baseline)")
    show(args.clean, args.attributed, args.runs, None, "control")
    for number, store in enumerate(args.stores, 1):
        print(f"\nStore {number} (paths and payloads omitted)")
        for mode in ("vector", "lexical", "hybrid"):
            show(args.clean, args.attributed, args.runs, store, mode)


if __name__ == "__main__":
    main()
