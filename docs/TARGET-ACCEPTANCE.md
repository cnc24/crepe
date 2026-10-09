# Target architecture acceptance (v1)

Scope: the user-provided “Crepe – Zielbild & Architektur”, design v0.1,
8 October 2026, pages 2–11. The named profile Chocolate supersedes the earlier
Nutella name. The target explicitly excludes GUI, distributed clusters,
decryption, active blocking and 100-Gbit/s specialization from v1. JA4, sFlow,
AF_PACKET/AF_XDP and external-plugin distribution/hot reload are later work.

This checklist records implemented paths and required acceptance checks; a row
is not a claim of unbounded completeness, lossless capture or endpoint emulation.

| Target | Implementation | Acceptance evidence |
| --- | --- | --- |
| One CLI and modular Rust engine | 17 crate boundaries; friendly aliases plus normal commands; no-argument help | Architecture check; CLI tests |
| Composable profiles and explicit module contracts | `plan`, repeated `--profile`, built-in manifests, dependencies and disable conflicts | Profile plan integration test |
| Bounded capture/flow/reassembly, loss visibility | Existing queues/budgets/anomalies; instance IDs; new-SYN tuple reuse boundary | Flow tests, worker identity tests, live/pressure checks |
| Consistent typed CQL | Shared event predicate AST for packet execution, historical SQL lowering and CPL; existing compatibility frontends | Predicate parity tests; storage and packet tests |
| Live and historical aggregation | Shared historical pipeline planning over bounded live windows or Parquet | Query/window and platform tests |
| CPL v1 reactions | Typed `on/where` rules; notice, tag, metric and log; rule/program versions and parent IDs | CPL grammar and end-to-end tests |
| Intel and central notices | Indicators, versioned sources; central deduplication/rate limits and suppression counts | Security/policy and pipeline tests |
| Separate raw/telemetry retention | Opt-in raw cache, live rotation, byte/time limits, atomic manifest, `raw-prune`; independent security/telemetry cutoffs | Retention/expiry and live-rotation tests |
| Reassembly packet evidence | Bounded packet reference sets survive TCP reorder/retransmit and IP fragmentation | Export/replay test with fragmented, reordered TLS |
| Original evidence lookup | Automatic retained-file lookup; hash checks; safe multi-packet export; explicit unavailable state | Changed/missing/expired capture tests |
| Common incident timeline | Instance trace, DNS/TLS/CNAME relations, Intel/policy parents, `timeline --related` | Synthetic DNS→TLS→policy→packet story |
| Built-in/external module isolation | Built-in manifests; existing versioned WIT/component sandbox, fuel/memory limits and failure isolation | Plugin tests and architecture check |
| Linux-first, Mac development | Linux/macOS builds and capture smoke tests; DEB/RPM | Release CI on the exact committed revision |

## Bounds are part of the contract

Evidence records the observed input packets for a directional analysis state,
including needed context and possibly retransmissions; it is not a byte-minimal
proof or proof that unseen traffic never existed. At most 4096 packet references
are retained per state, charged to its memory budget. Overflow is explicit and
never upgraded to complete. Older events retain their legacy single-anchor scope.

Raw retention is opt-in. Original imports are copied unchanged; live PCAP chunks
rotate by bytes, record count, source context and periodic ticks. Retention applies
only to manifest-owned copies, never user originals or historical observations.
The operator controls the byte/time policy. A stopped process cannot execute a
retention timer: use `raw-prune` for offline cleanup. Crash-interrupted chunks are
not published as complete evidence. Telemetry retention uses copy-based `compact --since-ms`, with an independent
`--security-since-ms` cutoff. Raw copies stay owned by the original store;
compaction does not copy its raw cache.

A correlation is inferred from observed context. Cross-source matching is opt-in;
it cannot establish clock alignment. Missing timestamps, encrypted metadata and
unsupported/ambiguous DNS chains are not fabricated. Timeline output declares
truncation. Live and historical selections retain explicit row/byte/time limits.

CPL is the declarative v1 language in the target, with the four specified passive
actions. It is not a general-purpose scripting language or Zeek/Suricata syntax
compatibility layer. Generated policy effects are not fed recursively into rules.
