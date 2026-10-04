> Private prototype planning record, not a published release or license grant.
> Current publication acceptance is defined in RELEASE-1.1.md.

> Scope correction: this document records the earlier, narrower release plan.
> See [original-design status](DESIGN-STATUS.md) for the unmet full-design 1.0 gates.

# Full-platform 1.0 acceptance evidence

The full analysis-platform target includes reassembly, DNS/TLS, flow export
collection and historical analytics. The release gate checks these behaviors;
a version bump alone is not acceptance. Linux and macOS CI must pass for the
release revision before the v1.0.0 tag is created.

| Stage | Implemented behavior | Reproducible evidence |
| --- | --- | --- |
| Foundation | Cargo workspace, typed packet CQL, PCAP/PCAPNG, live capture/export, wire flow accounting | capture/CLI/query/flow tests; smoke-live.py |
| Modular analysis | Acyclic crate boundaries, borrowed packet views, bounded directional TCP, DNS UDP/TCP, explicit anomalies | check-architecture.py; stream/analysis tests; smoke-dns.py |
| Reassembly and L7 | IPv4/IPv6 fragments, TCP sequence/overlap/reset/half-close handling, passive flow state, TLS Hello, HTTP/1.x and SSH basics | fragment/protocol tests; generated fragment/protocol fixtures; real local TLS/HTTP/SSH servers in smoke-platform.py |
| Flow collection | NetFlow v5/v9/IPFIX, source-port/domain-scoped templates, expiry/replacement, sequence/restart notices, sampling fields/options | collector tests including 10,000-message session and resource limits; three actual local UDP exporters in smoke-platform.py |
| Historical analytics | Atomic Parquet batches, Arrow/DataFusion, event/conversation correlation, trace/timeline, CQL projection/group/sort | store tests (uncommitted invisibility, restart, multi-part aggregation, idempotency, abort, unknown schema); engine stable-ID tests; mixed-source CLI smoke |
| Configuration | Validated/versioned TOML, implemented profiles, persistent sensor/event/conversation/flow-instance identity, bounded observational notices | strict configuration tests; deterministic same-input imports; documented SCHEMA.md |
| Hardening | Stable code/schema policy, fuzz target, adversarial corpus, streaming baseline, deterministic archive format, operations/recovery docs | 20,000-case stable mutation test; instrumented libFuzzer/ASan run; 2-million-packet soak; package.py checksums; Linux/macOS CI matrix |

The exact supported semantics and exclusions are in OPERATIONS.md and
SCHEMA.md. In particular, passive TCP state is not endpoint ACK validation;
HTTP is initial metadata, TLS is not decryption, historical flow IDs identify
scoped conversations, and options sampling is retained without guessing
counter scaling. These boundaries are part of the 1.0 contract.

Advanced AF_XDP tuning, distributed clustering, full DPI, a web UI and
external plugin execution are outside this release. No active blocking.
