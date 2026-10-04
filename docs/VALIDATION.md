
## 1.0 platform acceptance (2026-10-04)

Local host: Apple M2 Pro, macOS, Rust 1.99.0. All generated test traffic
used loopback or synthetic fixture bytes. Repository visibility remains
private. See GitHub Actions for the Linux/macOS release-revision gate.

Commands used for the final gate:

```
python3 scripts/check-architecture.py
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo test --workspace --locked
cargo build --release --all-features --locked
python3 scripts/smoke-live.py
python3 scripts/smoke-dns.py
python3 scripts/smoke-platform.py
python3 scripts/benchmark.py --packets 2000000
cargo +nightly fuzz run parsers -- -max_total_time=30 -max_len=65536 -rss_limit_mb=512
python3 scripts/package.py
```

The instrumented ASan/libFuzzer run completed **711,905 inputs in 31 seconds**
without a crash. This is a bounded smoke campaign, not exhaustive assurance.
Nightly Rust and cargo-fuzz were installed for this check; normal builds still
use stable Rust. The stable test suite separately exercises 20,000 mutated
inputs and a 10,000-datagram collector session with bounded state.

Synthetic 2,000,000-packet UDP baseline, optimized build, output discarded:

| Operation | Seconds | Packets/s | Peak child RSS reported by OS |
| --- | ---: | ---: | ---: |
| read + JSON + UDP predicate | 3.945 | 507,001 | 19,480,576 bytes |
| bidirectional flows | 0.828 | 2,414,485 | 19,742,720 bytes |
| analyze (non-DNS UDP fast path) | 0.417 | 4,801,012 | 19,742,720 bytes |

This is a low-entropy synthetic streaming baseline, **not** a TLS/reassembly,
DataFusion, live-capture or line-rate throughput claim. RSS is the cumulative
maximum over child processes in the benchmark, not a precise per-command heap
measurement. Background work on the development Mac was not controlled.

Storage tests exercise 1,100 rows spanning multiple Parquet parts, empty-store
queries, invisible uncommitted data, writer exclusion, restart, aggregation,
repeat-import rejection, abort cleanup and unknown-schema rejection. Engine
checks correlate reconstructed TLS/DNS with packet/flow rows and reproduce
identities in a separate store. Real local TLS (temporary self-signed test
certificate), HTTP and SSH traffic completes capture → metadata → storage.
The test certificate, captures and stores are removed after each smoke run.

A second seeded ASan/libFuzzer campaign completed **819,803 inputs in 31
seconds** without a crash, using generated packet/application/IPFIX seeds.
An additional real UDP collector run ingested 1,000 exports, isolated one
malformed datagram, committed on SIGINT, and returned the exact expected
aggregate after restart. Historical pre-1970 millisecond rounding has a
regression test; import hashes are checked again before atomic commit.
The DNS-change notice test deduplicates repeated records and verifies that
many distinct RRsets cannot exceed the configured notice-cache byte budget.


## Direct recipe correction — 2026-10-04

Local macOS verification after reconciling the original design:

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo clippy -p crepe-cli --all-targets --locked -- -D warnings`
- `cargo test --workspace --all-features --locked`
- `cargo test --workspace --locked`
- `cargo build --release --all-features --locked`
- `python3 scripts/check-architecture.py`
- `python3 scripts/smoke-recipes.py`: bare Choclate in a pseudo-terminal,
  real loopback DNS/flow capture through Choclate and UDP NetFlow through Banane.
- `python3 scripts/smoke-platform.py`: v5/v9/IPFIX, persistence/query/trace,
  actual local HTTP/SSH/TLS traffic.

All passed. Recipe tests verify the corrected profile meanings, custom Maison
configuration, invalid selections, collector UDP URL syntax and stable errors.
The smoke script removes its captures/stores. The existing original-design
feature gaps are tracked in DESIGN-STATUS.md; these checks do not close them.


## Platform extension — 2026-10-04

Local macOS Apple M2 Pro, Rust 1.99.0: workspace all-feature tests and strict
Clippy passed after adding the security/files/component crates, streaming
pipeline, live checkpoints and historical query extensions. Real loopback
capture, DNS UDP/TCP, HTTP/SSH/TLS, NetFlow v5/v9/IPFIX and direct recipe smoke
checks passed. The service smoke discovered an accepted-socket nonblocking
behavior on macOS; the endpoint explicitly switches accepted sockets to
blocking mode with bounded read/write deadlines.

The expanded ASan/libFuzzer target (including HTTP file hashing and indicator
feeds) completed **1,218,834 runs in 46 seconds**, without a crash. Criterion
quick-mode medians: CQL parse ~986 ns, predicate evaluation ~12.2 ns, HTTP
header inspection ~136 ns, small-body SHA-256 ~514 ns. These are synthetic
microbenchmarks under concurrent background work, not production throughput.
Native DEB/RPM and the final revision's Linux CI are separate validation gates.


## Live/operations hardening — 2026-10-04

The later local checks cover combined packet/export capture into one store,
live CQL windows emitted before EOF, explicit tolerant decoding, conservative
BPF superset tests including stacked VLANs/fragments, ZSTD partitioned stores,
copy-based compaction/retention and legacy lock migration. Real SIGKILL recovery
retains prior checkpoints and restarts without a stale modern lock. Parallel
worker tests compare 1/2/4-worker reassembly/event counts and exercise output
failure without a shutdown deadlock.

A 60-second optimized synthetic pressure run processed **5,915,172 packets**
and emitted **17,745,516 observations**, including **5,915,172 capacity/incomplete
anomalies** under deliberately small analysis budgets. Four workers share only
32 streams and 8 KiB of configured TCP buffers; queued buffers/flow tables and
runtime memory are additional. Independently sampled peak process RSS was
**147,488,768 bytes**, below the 512 MiB test ceiling. This deliberately churns
state and measures bounded behavior, not loss-free full-protocol throughput or
multi-day production uptime. Reproduce with the `pressure` example and
`scripts/soak.py --seconds 60`.


The 1.1 candidate adds concurrent hot-journal/Parquet snapshot tests across
50 rotations: counts stay monotonic without duplicates, and aborted provisional
rows disappear while durable checkpoints survive. The service smoke queries
DNS data before the first Parquet checkpoint, then tests clean and forced
shutdown. The final instrumented parser/file/indicator/CQL-prefilter campaign
completed **443,266 runs in 31 seconds** without a crash. Linux, macOS and
native Fedora package jobs passed during private development; this publication
candidate requires its own CI run before tagging.
