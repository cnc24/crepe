# v0.3 local validation — 2026-10-04

Executed on the prepared Mac with Rust/Cargo 1.99.0. All checks passed:

| Check | Result |
| --- | --- |
| `python3 scripts/check-architecture.py` | Nine crates obey production dependency boundaries |
| `cargo fmt --check` | Passed |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | Passed without warnings |
| `cargo test --workspace --locked --quiet` | 55 tests passed |
| `cargo test --workspace --all-features --locked --quiet` | 56 tests passed |
| `cargo build --release --all-features --locked` | Passed |
| `python3 scripts/smoke-live.py` | Existing live capture/replay/flow/deadline/Ctrl-C test passed |
| `python3 scripts/smoke-dns.py` | Real local UDP and TCP DNS capture/export/analysis passed |
| `crepe analyze fixtures/dns.pcap --format table` | Five valid query/response events, no duplicate retransmission event |
| `crepe analyze fixtures/dns-malformed.pcap --format csv` | Explicit malformed DNS and incomplete TCP anomalies |

CLI commands used `./target/release/crepe`. Both smoke scripts used existing
user BPF permissions on `lo0`, without local sudo or permission changes. The DNS
server listened on ephemeral 127.0.0.1 ports and answered only synthetic
`example.test.` requests with 203.0.113.7. TCP requests/responses were written in
separate chunks. Temporary captures were removed; no external DNS lookup occurred.

The deterministic TCP fixture separately guarantees reordered packet coverage.
Tests verify every split of a sample byte stream, sequence wrap, pending/delivered
overlap conflicts, retained-history limits, FIN gaps, final pure ACKs, pipelining,
midstream markers, RST cleanup, timeout/capacity/global-byte budgets, DNS pointer
validation, malformed record sizes and truncation. These are regression and
adversarial tests, not a claim that a dedicated fuzz campaign is complete.

Ubuntu/macOS CI repeats the architecture check, portable/live-enabled tests,
release build, fixture regeneration and both live smoke scripts. CI status belongs
to the specific commit's GitHub Actions run.

---

# v0.2 local validation — 2026-10-04

Executed on the prepared macOS development machine with Rust/Cargo 1.99.0.
All checks below passed. The actual live test used the user's existing BPF
permissions, without changing system permissions or using sudo locally.

| Check | Result |
| --- | --- |
| `cargo fmt --check` | Passed |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | Passed, no warnings |
| `cargo test --workspace --locked` | 36 tests passed |
| `cargo test --workspace --all-features --locked` | 37 tests passed |
| `cargo build --release --all-features --locked` | Passed |
| `python3 scripts/smoke-live.py` | Passed on `lo0` |
| `crepe interfaces` | Successfully listed local interfaces |
| `crepe read example.pcap 'dst.port in [443, 53]' --format csv --limit 2` | Two matching packet rows plus CSV header |
| `crepe flows fixtures/flows.pcap --format json` | Three flow records with correct FIN/RST/EOF reasons |

The CLI commands above used `./target/release/crepe` from the repository root.

The live test sent a UDP request and reply between two ephemeral ports bound to
127.0.0.1, captured exactly those packets through libpcap, exported a PCAP,
replayed it and compared the complete packet events. It then verified one flow
with one packet in each direction. A quiet one-second capture terminated on
time, and Ctrl-C stopped a separate quiet capture cleanly. Temporary captures
were removed after testing; no real network traffic was committed.

Automated tests also cover flow capacity eviction, idle and active deadlines,
out-of-order timestamps, VLAN/interface isolation, both FIN directions, RST,
missing timestamps, PCAP no-overwrite behavior, CSV shape, port-list type errors,
early stopping before a damaged file tail and native loopback byte order on export.

CI repeats offline and live-enabled tests, release examples, deterministic
fixture regeneration and the same bounded loopback smoke on Ubuntu and macOS.
See the GitHub Actions run attached to the corresponding commit for CI results.
