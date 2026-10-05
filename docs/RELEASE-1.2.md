# Crepe 1.2.0 validation

This release corrects `chocolate`, adds libpcap packet filters and improves human
packet output. It preserves JSON/CSV packet schemas and keeps `choclate` as an
alias. [Changes](../CHANGELOG.md) · [Commands and filters](OPERATIONS.md)

Local validation on Apple Silicon/macOS 27:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --all-features --locked
cargo build --release --all-features --locked
python3 scripts/check-architecture.py
python3 scripts/licenses.py --check
python3 scripts/smoke-live.py
python3 scripts/smoke-recipes.py
python3 scripts/compare-packet-tools.py --nfpcapd /path/to/nfpcapd --output /new/path
```

The final packet/capture test targets were rerun after fixing native DLT mapping
for raw-IP inputs. CLI regression coverage includes both spellings, unchanged
machine output, tcpdump/CQL selection equivalence on the supplied PCAP/PCAPNG
fixtures, TCP/DNS summaries, unknown timestamps and explicit portable-build
errors for unavailable BPF. Capture tests cover Ethernet, raw IP and native
loopback BPF, invalid expressions and explicit rejection of truncated-frame
wire-length ambiguity. Live smoke tests exercise positional BPF on loopback.

The external-tool comparison passed all 43 checks; see the
[method, commands and results](PACKET-FLOW-COMPARISON.md). nfdump/nfpcapd were
installed only for the comparison and are not dependencies of Crepe.

Official release assets are taken from the GitHub CI run for the release commit.
CI separately tests the default and all-feature workspace, builds on Linux and
macOS, runs synthetic/live checks, and creates/installs Debian and Fedora packages.
Each downloadable asset has a SHA-256 checksum. Available targets: macOS arm64,
Linux x86-64 tar archive, Debian amd64 and Fedora x86-64. See the release's CI
run for platform-specific logs; local Mac tests alone do not establish Linux
compatibility.

Known scope: BPF needs the `live` build feature (included in release binaries).
The userspace BPF evaluator rejects snaplen-truncated frames rather than silently
misinterpreting wire length; see [details](OPERATIONS.md#packet-filters-tcpdumpbpf-or-cql).
The human packet view is a compact summary, not every tcpdump protocol decoder.
It uses UTC time-of-day, absolute TCP sequence/ACK numbers and numeric endpoints.
Historical CQL and nfdump flow syntax are separate languages. Existing platform
limits in [DESIGN-STATUS.md](DESIGN-STATUS.md) still apply.

## 1.2.1 flow presentation follow-up

The wide flow table is replaced with 80-column wrapped summaries. Added tests
cover UTC dates, negative timestamps, duration across midnight, long IPv6
addresses, maximum counters, directional flags/bytes and file-end versus TCP
close. The CLI suite also retains JSON/CSV flow-counter checks. Formatting,
strict all-feature Clippy, CLI tests with and without optional features, release
build and the 43-check external-tool comparison are rerun for this patch.
