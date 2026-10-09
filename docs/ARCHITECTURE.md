# Architecture

Seventeen focused Cargo crates form an acyclic production dependency graph.
`scripts/check-architecture.py` checks the allowed edges from Cargo metadata.
Every crate forbids unsafe Rust; third-party libraries may contain unsafe code.
Tests may depend on fixture/capture helpers without introducing production cycles.

| Crate | Responsibility | Internal production dependencies |
| --- | --- | --- |
| crepe-files | Bounded HTTP body metadata and SHA-256 | core |
| crepe-security | Indicators, CPL actions and rule versions | core, query |
| crepe-plugin | Capability-free component API and guest resource budgets | core |
| crepe-core | Packet, endpoint, event and error contracts | None (Serde only) |
| crepe-packet | Borrowed link/network/transport decoding | core |
| crepe-capture | PCAP/PCAPNG streaming, export, optional libpcap | core, packet |
| crepe-query | Shared typed event CQL and packet compatibility frontend | core |
| crepe-flow | Bounded bidirectional wire accounting and passive TCP state | core |
| crepe-stream | Bounded directional TCP sequence reconstruction | core |
| crepe-fragment | IPv4/IPv6 datagram reconstruction | core |
| crepe-dns | Bounded DNS wire parser | core |
| crepe-protocol | TLS Hello, HTTP headers and SSH banners | core |
| crepe-analysis | Stream lifetimes, application framing, anomalies, IP processor | core, packet, flow, stream, fragment, dns, protocol, files |
| crepe-collector | NetFlow/IPFIX datagrams, templates, exporter sessions | core |
| crepe-storage | Arrow/Parquet transactions, identity hashing, historical CQL/DataFusion | core, query |
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

Schema-2 historical `flow_id` is an observed flow-instance identity anchored to
a capture record; `conversation_id` keeps the endpoint-tuple grouping separately.
A bounded packet ancestry index applies the same identity to associated L7 events.
Schema-1 stores retain their original tuple semantics and remain read-only.
The engine's correlation module relates direct DNS answers and visible TLS SNI
using explicit context/TTL/time constraints. The CLI retrieves source-event chains
and verifies capture content hashes before exporting a referenced packet.


Live worker orchestration is confined to `crepe-engine/src/workers.rs`.
Canonical IP-pair/link affinity preserves directional and fragment
state without shared mutable flow tables. Bounded standard-library channels
carry owned capture buffers to workers and typed observations back to one sink.
Storage/security/components remain centralized. Failed output drops the result
receiver before joining workers, so blocked senders cannot strand shutdown.
Offline processing uses the serial pipeline to retain reproducible ordinal IDs.
Storage maintenance and historical UDFs are separate modules; persistent OS
advisory locks guard writers and copy-based compaction across process crashes.

The shared event predicate AST belongs to query. Packet evaluation, CPL and
historical SQL lowering reuse its fields, types and SQL-null semantics; packet
compatibility shortcuts retain their dedicated parser. The historical pipeline
planner is also reused by bounded live aggregation. Security never imports storage.

Packet references pass through IP fragment assembly and directional TCP analysis.
The engine resolves instance ancestry, policy parents and central notice limits.
Raw retention is an opt-in engine service under the store writer lock. Live input
is retained before dispatch to workers; complete chunks publish atomically.
Telemetry and raw retention therefore have independent lifetimes.
