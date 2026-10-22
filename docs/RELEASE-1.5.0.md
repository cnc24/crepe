# Crepe 1.5.0 — capture statistics and report tables

- `read -c N` and `capture -c N` stop after N matching packets. The existing
  `--limit` remains available; verbose/hex output may use multiple text lines.
- `stats` reads PCAP/PCAPNG directly: summary, hierarchy, protocols, source
  talkers, endpoints, IP pairs, destination ports and TCP flag/filter counts.
- Named presets, selected TShark `-z` aliases and the existing CQL/BPF filters
  share explicit counting semantics. IPv4/IPv6 aliases select their family.
- Terminal/Markdown/CSV/JSON output supports report workflows. `-o` atomically
  creates a new file and refuses overwrite. Exact groups are memory-bounded;
  omissions, malformed skipped records and overlapping counts are explicit.
- Root help separates traffic analysis, investigation/storage and auxiliary
  commands. Packet/statistics help groups selection/limits and display/export,
  with syntax explanations and executable examples.

No new dependency or historical schema migration is required. Protocol hierarchy
is packet-local and does not imply TShark's complete dissector/reassembly coverage.
`conversations` aggregates IP pairs across ports; use `flows` for connection
instances. `syn` includes SYN-ACK; `syn-only` excludes ACK. Bytes are original
frame lengths including link headers. See the
[English manual](OPERATIONS.md#capture-statistics-and-report-tables-150).

## Validation

Local macOS ARM64 checks:

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo test --workspace --all-features --locked`: 145 tests.
- `cargo test --workspace --locked`: 140 tests.
- `cargo build --release --all-features --locked`
- Architecture and locked third-party license checks.
- 87 real TShark/tcpdump checks: count/byte parity, hierarchy nodes, source and
  endpoint rankings, omitted groups, CQL/BPF and wildcard counts, and `-c` packet export.
- 50 existing packet-filter/HTTP compatibility checks, including the Wireshark
  HTTP sample, plus the live loopback capture/replay test now exercising `-c`.
- Regression cases cover empty PCAP, malformed packets, fatal container errors,
  PCAPNG, exact group limits, JSON/Markdown/CSV and atomic no-overwrite export.

Upstream manuals: [TShark](https://www.wireshark.org/docs/man-pages/tshark),
[tcpdump](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in).
The comparisons cover the documented subset; no universal dissector or syntax
compatibility is claimed. Release binaries are built by the Linux/macOS/RPM CI
from the exact release commit.
