# Crepe 1.4.0 acceptance notes

The target v1 investigation path now connects capture, flow, reassembled L7,
Intel/CPL findings, related timelines and hash-verified packet evidence.
[Target acceptance](TARGET-ACCEPTANCE.md) maps the requirements and bounds.

## Upgrade and compatibility

Historical schema remains 2; 1.3 stores remain usable. Schema-1 stores remain
read-only: retain them and reimport available originals into a new directory.
Analysis JSON schema 2 adds bounded packet evidence; flow JSON schema 4 adds the
new-SYN tuple-reuse end reason. Packet JSON stays schema 2. Old events keep their
original evidence scope. New packet filter predicates use shared three-valued
missing-field semantics. Existing syntax compatibility frontends remain.

Raw retention is **opt-in** (`--keep-raw` or `[raw] enabled = true`). Defaults are
256 MiB total, 16 MiB rotation and 24 hours. User originals are never deleted.
Raw expiration does not delete historical observations. Compaction uses separate
telemetry/security cutoffs and does not copy the original store's raw cache.

## New workflows

- `plan --profile chocolate --profile banane` resolves versioned manifests and
  dependencies. Conflicting disabled dependencies fail before capture.
- `policy_rules = "config/target.cpl"` enables declarative on/where rules with
  notice, tag, metric and log, parent IDs, rule/program versions and bounds.
  Collector recipes also use the shared execution engine; enable policy there.
- `evidence STORE EVENT_ID --write evidence.pcap` discovers retained originals
  or live chunks, verifies hashes and exports reconstruction inputs atomically.
- `timeline STORE --related EVENT_ID` provides bounded one-hop DNS/TLS context;
  `correlate --cross-source` explicitly allows uncertain cross-source clocks.
- `raw-prune STORE` applies raw retention while capture is stopped.
- `compact SOURCE --output DEST --since-ms ... --security-since-ms ...` keeps separate
  security/telemetry horizons without changing the source store.

## Reproducible acceptance

`fixtures/target-reassembly.pcap` contains DNS and a TLS ClientHello with TCP
reordering, retransmission and IP fragmentation. Integration tests ingest it,
evaluate all four CPL actions, follow a notice to five contributing packets,
export/replay the ClientHello, rotate live chunks, reject tampering, expire raw
copies and verify that metadata and the original input survive. Other tests
cover typed predicate parity, CNAME TTLs, profile dependencies, SYN reuse and
independent security retention. Live recipe smoke tests send a real NetFlow v5
datagram through the CPL collector path.

Local verification on macOS ARM64 (9 October 2026):

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo test --workspace --all-features --locked`: 141 tests passed.
- `cargo test --workspace --locked`: 136 tests passed.
- `cargo build --release --all-features --locked`
- `scripts/check-architecture.py`, `scripts/licenses.py --check`: passed.
- Live capture/replay, recipes, CPL collector, daemon metrics/checkpoints/crash
  recovery, DNS UDP/TCP, HTTP/SSH/TLS and NetFlow v5/v9/IPFIX smoke tests passed.
  The daemon test verifies a real CPL counter at the Prometheus endpoint.
- 50 TShark/tcpdump compatibility checks and 43 tcpdump/nfdump/nfpcapd checks
  passed, including the Wireshark HTTP sample used by earlier acceptance.
  These selected datasets establish no universal tool equivalence.
- The generated 200,000-packet offline benchmark completed for read/flows/analyze
  within bounded memory. This is a synthetic baseline, not a line-rate claim.

Release assets are built by the Linux/macOS/RPM CI gates from the published
revision; use the release commit and workflow results to verify provenance.

## Explicit limits

Provenance is the bounded observed-input set, including reconstruction context;
it is not byte-minimal or proof of lossless capture. Reference overflow is visible.
Correlation is inference, never proof of causality or clock synchronization.
CPL v1 is passive and declarative, not a general scripting runtime. GUI, clusters,
decryption, active blocking and broader future protocols remain outside v1.
