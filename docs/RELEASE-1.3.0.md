# Crepe 1.3.0 acceptance notes

## Upgrade first

**New stores use historical schema 2. Schema-1 stores remain readable but are
read-only in 1.3.0.** Stop existing writers before upgrading. Keep old stores and
reimport available original captures into a **new directory** to obtain instance
identities. Without originals, retain the legacy history with its tuple-level
identity semantics. Do not edit `schema.json` to simulate migration.

Flow JSON uses schema 3 and adds `first_sequence`; packet JSON remains schema 2.
No third-party dependency or license was changed for this milestone.

## Implemented target-architecture slice

- Historical `flow_id` identifies an observed flow instance. `conversation_id`
  retains sensor/source/link-scoped tuple grouping. Closed TCP connections that
  reuse endpoints no longer collapse into one historical trace.
- A bounded ancestry index associates packet/application events with instances.
  Serial and affinity-worker paths use the same identity function. Unsupported
  or expired assignments are explicitly `unassigned`.
- `correlate STORE` relates direct DNS A/AAAA answers to visible TLS SNI, checking
  client, IP, sensor, source, link context, time window and DNS TTL. Results report
  `inferred`, `ambiguous` or `unmatched`, with event/flow and Intel references.
- `evidence STORE EVENT_ID --capture ORIGINAL.pcap` follows event references and
  verifies the original file's content hash before locating a packet. `--write`
  publishes one complete packet export to a new file without overwriting files.
- Help, schema documentation and the English operations manual explain the new
  commands, bounds and upgrade procedure.

## Local verification (macOS ARM64, 8 October 2026)

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo test --workspace --locked`: 123 tests passed.
- `cargo test --workspace --all-features --locked`: 129 tests passed.
- `cargo build --release --all-features --locked`
- Architecture dependency and locked-license checks passed.
- Live capture/replay, direct recipes, DNS UDP/TCP, daemon shutdown/recovery,
  HTTP/SSH/TLS, historical queries and NetFlow v5/v9/IPFIX smoke tests passed.
- 50 TShark/tcpdump compatibility checks and 43 tcpdump/nfdump/nfpcapd comparison
  checks passed with the datasets and normalization described in
  [1.2.3 acceptance](RELEASE-1.2.3.md). This is not universal equivalence.
- An actual store written with the 1.2.4 release remained queryable/traceable;
  1.3.0 rejected writes and left its schema-1 manifest unchanged.

`fixtures/target-story.pcap` is generated locally: one DNS answer followed by two
TLS connections reusing the same endpoints. Integration tests verify distinct
instance IDs, one conversation ID, separate traces, DNS/TLS associations, Intel
references, packet evidence and one-packet export. Serial, two-worker and
four-worker identities are compared. Negative cases cover TTL expiry, wrong
client/source/sensor/link/IP, absent timestamps/SNI/identity, truncated DNS,
ambiguous candidates, unrelated/missing originals and existing export paths.

## Explicit limits

These are passive observed flow instances, not proof of endpoint TCP state.
Timeouts, capacity eviction and observed closes define boundaries. Unobserved
closes remain uncertain. Correlation is bounded and on demand; it does not infer
causality, cross-capture relationships, CNAME chains or hidden SNI. A referenced
packet is not complete reassembly-byte provenance. Automatic raw capture
retention/discovery, full CPL, unified query AST and profile dependency planning
remain future work; this release does not claim full completion of the target PDF.
