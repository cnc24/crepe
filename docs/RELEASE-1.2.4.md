# Crepe 1.2.4 acceptance notes

This maintenance release fixes durable flow imports, improves command help and
adds the project logo. It does not change historical schema version 1 or claim
completion of the target correlation architecture.

## Reliability and usability

- `flows FILE --store DIR | head` finishes the requested import after the reader
  closes stdout. A regression capture with 16,000 records verifies the stored flow
  count against a complete import. Capture/storage errors still fail the command.
- Historical flow predicates are recognized inside parentheses and negations,
  including when a packet-like predicate appears first.
- Explicit capture-only options on a stored query are rejected, even if their
  values equal the defaults. Count sorting explains the required group/count stage.
- Flow imports report preparation, record progress, verification and commit on
  stderr. Packet JSON/CSV remain free of banners and progress output.
- Pure IP/port/protocol CQL skips application recognition. Streaming flows no
  longer require creation of an unused temporary directory.
- Short/long help explains profile selection, storage, filters, examples and units.
  `logo` prints the ASCII mascot; interactive root help displays it unless serious
  mode is selected. The image logo appears in the README and packaged assets.

## Local verification (macOS ARM64, 8 October 2026)

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo test --workspace --locked`: 118 tests passed.
- `cargo test --workspace --all-features --locked`: 124 tests passed.
- `cargo build --release --all-features --locked`
- Architecture and locked-dependency license checks passed.
- The comparison scripts passed 50 TShark/tcpdump checks and 43
tcpdump/nfdump/nfpcapd checks. See [1.2.3 acceptance](RELEASE-1.2.3.md) for inputs,
versions and the distinction between frame bytes and directional IP bytes.

A local release-to-release microbenchmark repeated the first valid DNS packet in
`fixtures/dns.pcap` 200,000 times. Five alternating runs per binary used `read`
with JSON output discarded. Median elapsed time changed from 0.298 s to 0.254 s
for `proto == udp`, and from 0.192 s to 0.148 s for `proto == tcp` (no matches).
This is approximately 15% and 23% less elapsed time on those synthetic workloads,
not a general throughput guarantee. First-run startup costs were larger.

## Remaining architecture work

Historical `flow_id` still groups the same endpoint tuple within a source; unique
flow-instance IDs exist in flow payloads but are not yet the universal trace key.
DNS/TLS cross-connection correlation and verified original-packet retrieval are
separate milestones. Existing stores are not silently reinterpreted or rewritten.
