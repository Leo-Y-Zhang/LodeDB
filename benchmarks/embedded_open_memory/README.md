# Embedded open and first-query memory

The probe opens a committed store read-only, optionally refreshes, then runs the
same query twice. Each stage reports elapsed time, current process memory, the
lifetime memory high-water mark, live allocated bytes, and the stage's heap peak.
On Linux, process memory is RSS (`VmRSS` / `VmHWM` from `/proc/self/status`); on
macOS it is the task's physical footprint. These metrics are not interchangeable.
`settled` reports steady residency after 1.5 seconds, without forcing the allocator
to release memory. Every mode runs in a fresh process.

To create a reproducible synthetic input (10,000 documents, 384 dimensions, 4-bit
vectors, seed 134, 4,096 generated terms plus six recurring phrases, about 64
tokens per document, one category metadata field):

```bash
cargo build --release --manifest-path benchmarks/embedded_open_memory/Cargo.toml \
  --target-dir target/embedded-open-memory/head
target/embedded-open-memory/head/release/create_store target/memory-store-10k
benchmarks/embedded_open_memory/run.sh --runs 3 target/memory-store-10k
```

Use `OPENBLAS_NUM_THREADS=1` for reproducible CPU threading. Reuse the generated
store for every revision; do not regenerate it between measurements. This
synthetic input is not the original issue's store, which is not in the repository.

`run.sh --base <revision> --runs 3 <store>` also builds the base revision with the
same probe, and compares byte-identical result dumps (including score bits) for
vector, lexical and hybrid queries, filters and two k values, on read-only handles
and writable copies after upsert/delete/persist/reopen. It never changes the
supplied store. The Rust core also has fixed-seed differential tests.

To repeat a saved baseline without recompilation, copy `embedded-open-memory`
and `results_dump` from the release directory before editing the core, then use
`run.sh --probe-dir <saved-binary-dir> --runs 3 <store>`. This runs the same stages
in fresh processes and allows measurements after other builds have finished.

## Component attribution (opt-in)

```bash
export OPENBLAS_NUM_THREADS=1 CARGO_BUILD_JOBS=3 JOBS=3
benchmarks/embedded_open_memory/run.sh --components --runs 3 target/memory-store-10k
```

This prints, for a no-store control and then for `vector`, `lexical` and `hybrid`
on each store, a table of live heap by component and a table of process residency.
It needs Python 3 (standard library only). The wrapper builds the probe twice in
the usual target directory, with `--features components` first and plain last, so
the normal binary is left in place. Every run is a fresh process without
`refresh()`. `--components` refuses `--base` and `--probe-dir` (exit 2): comparing
two instrumented builds is not supported. Without the flag, `run.sh` and the probe
behave and print exactly as before; the feature adds an optional `backtrace`
dependency to this crate only.

### How the heap is attributed

The probe's counting allocator, built with `--features components` and run with
`--components`, records the call stack of every allocation (no sampling), resolves
each distinct stack once, and keeps live bytes per component by address. A
reallocation keeps its original component. A thread-local guard keeps the
profiler's own allocations out of both its counters and the usual heap counter.
`dhat` was considered first, but it would have to be the global allocator itself
and it cannot take a per-component snapshot at an arbitrary stage boundary.

Each stage records the component split at the moment the stage's total live heap
was highest ("peak") and at the end of the stage ("done"/"settled"). A peak column
is one simultaneous split, so it adds up; freed temporaries appear in it and not
in the steady columns. The probe checks that the live split sums to the allocator
counter exactly at every stage end. `report.py` checks the peak split against the
counter (within 1%; rayon workers can order the two updates differently), the
attributed heap against a separate uninstrumented run (within 1%), that the live
split is identical across runs, and that the peak split moves by no more than
64 KiB between runs. It fails on any mismatch rather than printing.

Stacks are walked from the allocation toward `main`; the first frame whose
symbol path starts with a prefix below wins, so generic helpers (`alloc`,
`serde_json`) take the component of their caller. The table lives in
`src/components.rs`; prefixes are `lodedb_core::` paths unless shown otherwise.

| Symbol prefix | Component |
|---|---|
| `storage::lexical_store::`, `engine::DeferredTokenLists` | lexical source text |
| `storage::tvvf_store::`, `storage::tvim_delta::`, `storage::multivec_store::`, `vector::`, crate `turbovec::` | vectors |
| `storage::tvann_store::` | ANN sidecar |
| `storage::text_store::` | text store |
| `storage::state_journal::`, `storage::legacy::` | document state/metadata: JSON |
| `engine::index_from_loaded_store` | document state/metadata: maps |
| `lexical::bm25::` | BM25 serving index |
| any other `lodedb_core::` frame | core other |
| everything else (probe, std, allocations before `main`) | runtime other |

These are allocation sites, not owners: a string moved out of the parsed state
stays in the JSON row. "maps" covers the document records, chunk-owner maps and
field indexes built while opening. During a lexical or hybrid query the lexical
row also holds that query's transient parse of the source text. Every row is
printed even when it is zero, for example the lexical row on a store without a
`.tvlex` sidecar.

### Process residency

The process table comes from separate, uninstrumented runs (`--residency`, median
of `--runs`); RSS of an instrumented run is never used. On Linux it reads
`/proc/self/smaps_rollup`: `Rss`, `Pss`, `Private_Dirty`, `Private_Clean`,
`Anonymous`, file-backed (`Rss - Anonymous`) and `Swap`. `Private_Dirty + Swap` is
the closest Linux analogue of the macOS/iOS physical footprint; it is labelled as
an analogue and is not phys_footprint. "RSS - live heap" is everything the heap
split does not explain: the binary and shared libraries, native (C) allocations,
stacks, and allocator slack such as freed memory glibc has not returned. Resident
bytes are also summed per mapping kind from `/proc/self/smaps` (probe binary,
OpenBLAS, other shared libraries, stacks, heap arena, anonymous), using fixed
labels so no path is printed. Reading procfs costs a little memory itself. The
lifetime peak is the kernel's high-water mark since process start, so a query's
own RSS peak is hidden when the open peak is higher. On macOS the smaps columns
print `n/a` and the process columns are phys_footprint.

### Measured: seed-134 synthetic 10k store, Linux

`rust:1-bookworm` container (5 GiB memory limit), Rust 1.99.1,
`OPENBLAS_NUM_THREADS=1`, `run.sh --components --runs 3`. Heap in MiB; RSS medians
of three uninstrumented runs. This is Linux RSS on the synthetic store, not
phys_footprint on the maintainer's store, which is still to be measured.

| component | open peak | open done | vector settled | hybrid first query peak | hybrid settled |
|---|---:|---:|---:|---:|---:|
| lexical source text | 0.00 | 7.13 | 7.13 | 7.69 | 7.13 |
| vectors | 0.00 | 4.25 | 9.65 | 9.65 | 9.65 |
| ANN sidecar | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| text store | 0.00 | 5.16 | 5.16 | 5.16 | 5.16 |
| document state/metadata: JSON | 37.30 | 0.94 | 0.94 | 0.94 | 0.94 |
| document state/metadata: maps | 0.00 | 11.86 | 11.86 | 11.86 | 11.86 |
| BM25 serving index | 0.00 | 0.00 | 0.00 | 11.77 | 11.19 |
| core other | 0.01 | 0.03 | 0.10 | 0.23 | 0.19 |
| runtime other | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| live heap | 37.31 | 29.37 | 34.85 | 47.30 | 46.13 |

| RSS, MiB | no store | vector | hybrid |
|---|---:|---:|---:|
| lifetime peak after open | 4.9 | 60.8 | 60.7 |
| RSS at open done | 4.9 | 50.6 | 50.4 |
| RSS settled after first query | 5.0 | 51.3 | 60.4 |
| Private_Dirty + Swap (analogue), settled | 0.5 | 44.1 | 53.3 |
| RSS - live heap, settled | 5.1 | 16.6 | 14.5 |
| heap arena resident, settled | 0.1 | 43.6 | 52.9 |

The no-store process is 5.0 MiB: shared libraries 2.2, OpenBLAS 1.6, probe binary
1.0, almost no heap. The open heap peak is the state JSON alone: at that moment
nothing else is live, and 0.94 MiB of it is still live when the open returns.
The lexical source text held for BM25 is 7.13 MiB of live heap on every
read-only handle, including vector-only ones that never use it (20% of the
vector-only settled heap). The largest steady row is the per-document maps
(11.86 MiB); in hybrid mode the BM25 index adds 11.19 MiB. The RSS high-water
mark (about 60.8 MiB) is set during the open in every mode, about 18.5 MiB above
the open heap peak plus the no-store baseline; the heap counters cannot divide
that gap further. A vector-only handle settles at 51.3 MiB RSS, of which 16.6 MiB
is not live heap.
