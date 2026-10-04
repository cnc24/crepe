> Scope correction: this document records the earlier, narrower release plan.
> See [original-design status](docs/DESIGN-STATUS.md) for the unmet full-design 1.0 gates.

# Crepe implementation plan

This tracks the research design as incremental, tested releases. An unchecked
item is a future capability, not an implemented CLI command. The architectural
plan is broader than the current prototype; each milestone must retain bounded
state, stable error codes and local tests.

## Completed: v0.1 offline foundation

- [x] Cargo workspace with core library and CLI.
- [x] Typed IP/port/protocol data and packet events.
- [x] Typed CQL predicates, booleans, parentheses and CIDR matching.
- [x] PCAP/PCAPNG reading and Ethernet/IPv4/IPv6/TCP/UDP/ICMP decoding.
- [x] Table/JSON Lines output, French CLI diagnostics and stable codes.
- [x] Generated fixtures, automated tests, private repository and Linux/macOS CI.

## Completed: v0.2 capture and flow accounting

- [x] Optional libpcap capture and interface discovery; `sucre` alias.
- [x] Explicit BPF prefilter, CQL userspace filter, duration/count limits, Ctrl-C.
- [x] Raw IP, BSD loopback and Linux cooked capture decoding.
- [x] Filtered PCAP writing with no-overwrite behavior and replay tests.
- [x] CQL port lists, CSV output and early output limits.
- [x] Canonical bidirectional TCP/UDP flow keys, VLAN/interface isolation.
- [x] Directional counters, observed TCP flags, idle/active timeouts, FIN/RST endings.
- [x] Bounded flow table and timer index; deterministic capacity eviction.
- [x] Real local loopback UDP capture → PCAP → replay → flow smoke test.
- [x] Idle-interface timeout and signal shutdown tests.

This is flow accounting, not a complete TCP connection state engine. IDs are
local to one invocation. Filters on flows select packets before aggregation.
Raw packet output uses schema 2; consult README for exact semantics and limits.

## Completed: v0.3 modular analysis foundation

- [x] Nine focused crates with enforced production dependency boundaries.
- [x] Borrowed transport `PacketView` and optional capture backend isolated from CLI.
- [x] Bounded directional TCP reassembly: ordering, duplicates, wraparound and overlap errors.
- [x] DNS UDP/TCP framing, compressed names and common typed resource records.
- [x] Explicit malformed/incomplete/resource anomaly events; bounded analyzer state.
- [x] Synthetic protocol fixtures and real local UDP/TCP DNS capture/analysis tests.

This stage is **not 1.0**. The selected target is the full platform; the remaining
release gates are recorded in [docs/RELEASE-1.0.md](docs/RELEASE-1.0.md).

## Next: strengthen the streaming foundation

- [ ] Tolerant decode mode with explicit anomaly counters and truncation metadata.
- [ ] Conservative CQL→BPF pushdown with equivalence tests across supported links.
- [ ] Shared live/offline flow execution and processing-time expiry on quiet inputs.
- [ ] Sensor identity and persistent 128-bit flow/event IDs.
- [ ] Complete TCP state tracking (midstream, SYN reuse, retransmissions, half-close).
- [ ] Performance benchmarks, property tests and dedicated fuzz targets.
- [ ] Profiles/configuration with validation and explicit module dependencies.

## Next: bounded L7 and reassembly

- [ ] IPv4/IPv6 fragment reassembly, overlap anomalies and memory/time limits.
- [x] Directional TCP byte reconstruction with sequence wrap, retransmissions and out-of-order limits.
- [ ] Full connection lifecycle/reuse/window behavior and IP reassembly integration.
- [x] Borrowed PacketView and typed DNS/anomaly payloads.
- [ ] Persistent flow-correlated L7 event IDs.
- [x] DNS over UDP/TCP with compression-pointer limits and fixture coverage.
- [ ] Protocol detection followed by TLS ClientHello, HTTP/1.1 and SSH metadata.
- [ ] Make encrypted/absent metadata explicit; do not infer invisible TLS contents.

## Later: collectors, queries and storage

- [ ] NetFlow v5 ingestion, followed by exporter-scoped NetFlow v9/IPFIX templates.
- [ ] Template expiry, sequence tracking, sampling and bounded collector state.
- [ ] Historical Arrow/Parquet storage and DataFusion-backed queries.
- [ ] CQL flow/event fields, comparisons, projections and aggregation pipelines.
- [ ] Flow trace/timeline and stable links between packet, flow and L7 events.
- [ ] Notice/intelligence/policy framework with bounded matching state.
- [ ] Choclate/Banane/Suzette/Maison/Complète profiles after their engines exist.
- [ ] Worker-local state with canonical flow affinity after profiling justifies it.

AF_PACKET/TPACKET_V3, AF_XDP, distributed operation, full DPI, plugin execution
and a web UI are outside the current milestones. Automatic network blocking is
not part of the v1 design.
