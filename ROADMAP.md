# Crepe roadmap

Current release line: **1.5.x**. This replaces the obsolete prototype checklist;
completed work is recorded in [CHANGELOG.md](CHANGELOG.md), executable usage in
[the operating guide](docs/OPERATIONS.md), and the October architecture acceptance
in [TARGET-ACCEPTANCE.md](docs/TARGET-ACCEPTANCE.md).

## Implemented and tested

- Rust workspace; bounded packet/flow processing and Linux/macOS builds.
- Offline and live capture, link-layer records, CQL/BPF selection, packet exports.
- Bidirectional connection instances, IP/TCP reconstruction and DNS/TLS/HTTP/SSH.
- NetFlow v5/v9/IPFIX collection with exporter/template context.
- Parquet/DataFusion history, direct flow queries, correlation, trace and timeline.
- Composable profiles, module dependencies, bounded policy/Intel/notice processing.
- CPL v1 notice/tag/metric/log and original-packet evidence with opt-in raw retention.
- Capture statistics, report tables, canonical commands with French aliases.
- Self-update, archive/DEB/RPM packaging, local tests and release CI.

Instance IDs and history schema contracts are described in [SCHEMA.md](docs/SCHEMA.md).
These are not invocation-local tuple IDs. Packet prefilters and post-aggregation
flow queries are distinct; see `crepe flows -h`.

## Remaining extensions, not current compatibility promises

- Broader L7 decoding and transaction framing (HTTP/2, QUIC, DHCP and additional
  TLS metadata); no encrypted-content visibility is implied.
- Broader Wireshark/nfdump query compatibility and protocol dissection. The
  supported subset and reproducible comparisons are documented in OPERATIONS.
- Separate privileged capture helper, with a versioned IPC protocol and bounded
  queues; current live capture uses libpcap in the same process.
- External-plugin distribution/signing/hot reload, event-time streaming semantics,
  sFlow and alternative Linux capture backends when justified by measurements.

GUI, distributed clusters, active blocking, decryption and 100-Gbit/s tuning are
outside the October v1 target. No calendar or universal throughput promise is made.
