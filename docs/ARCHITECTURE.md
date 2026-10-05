# Architecture

Seventeen focused Cargo crates form an acyclic production dependency graph.
`scripts/check-architecture.py` checks the allowed edges from Cargo metadata.
Every crate forbids unsafe Rust; third-party libraries may contain unsafe code.
Tests may depend on fixture/capture helpers without introducing production cycles.

| Crate | Responsibility | Internal production dependencies |
| --- | --- | --- |
| crepe-files | Bounded HTTP body metadata and SHA-256 | core |
| crepe-security | Local indicator matching and observational policies | core |
| crepe-plugin | Capability-free component API and guest resource budgets | core |
| crepe-core | Packet, endpoint, event and error contracts | None (Serde only) |
| crepe-packet | Borrowed link/network/transport decoding | core |
| crepe-capture | PCAP/PCAPNG streaming, export, optional libpcap | core, packet |
| crepe-query | Typed packet CQL lexer/parser/evaluator | core |
| crepe-flow | Bounded bidirectional wire accounting and passive TCP state | core |
| crepe-stream | Bounded directional TCP sequence reconstruction | core |
| crepe-fragment | IPv4/IPv6 datagram reconstruction | core |
| crepe-dns | Bounded DNS wire parser | core |
| crepe-protocol | TLS Hello, HTTP headers and SSH banners | core |
| crepe-analysis | Stream lifetimes, application framing, anomalies, IP processor | core, packet, flow, stream, fragment, dns, protocol, files |
| crepe-collector | NetFlow/IPFIX datagrams, templates, exporter sessions | core |
| crepe-storage | Arrow/Parquet transactions, identity hashing, historical CQL/DataFusion | core |
| crepe-engine | Configuration, observations, policy notices, import orchestration | core, capture, packet, flow, analysis, collector, storage, security, plugin (optional) |
| crepe-cli | Arguments, IO, packet presentation, signal handling and operational commands | core, capture, packet, query, flow, dns, analysis, collector, storage, engine |

Core has no capture, database, CLI or runtime dependency. Packet views borrow
input bytes. IP/TCP reconstruction owns only bounded queues; analysis emits
owned observations. Packet accounting and application reconstruction remain
separate because reconstructed bytes are not original wire packets.

Storage accepts a neutral row envelope and does not depend on protocol parsers.
The engine maps packet, flow and application contracts to that envelope.
Collector similarly emits typed export records without binding UDP sockets;
the CLI owns the socket, wall-clock deadline, cancellation and diagnostics.
Parquet and DataFusion are confined to storage. Plugin execution is isolated in its own optional crate; the engine supplies only
observation envelopes. There is no HTTP server or background daemon in these libraries.

The historical `flow_id` is an explicit conversation correlation key. It
supports packet/analysis/flow timelines within a source. Payload flow instance
IDs and event IDs distinguish repeated connections. See SCHEMA.md for exact
identity scope; cross-sensor/time-window attribution is not guessed.


Live worker orchestration is confined to `crepe-engine/src/workers.rs`.
Canonical IP-pair/link affinity preserves directional and fragment
state without shared mutable flow tables. Bounded standard-library channels
carry owned capture buffers to workers and typed observations back to one sink.
Storage/security/components remain centralized. Failed output drops the result
receiver before joining workers, so blocked senders cannot strand shutdown.
Offline processing uses the serial pipeline to retain reproducible ordinal IDs.
Storage maintenance and historical UDFs are separate modules; persistent OS
advisory locks guard writers and copy-based compaction across process crashes.
