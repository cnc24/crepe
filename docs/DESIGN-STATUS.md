# Original design versus implemented behavior

The user-supplied [original design](DESIGN-ORIGINAL.md) is the planning source.
The [English manual](OPERATIONS.md) describes executable commands and precise
limits. Milestone/release acceptance is tracked in [RELEASE-1.1.md](RELEASE-1.1.md).

Version 1.1.0 was the initial source-available publication candidate. Current
target acceptance is tracked below; earlier private prototype history is not included.

| Area | Implemented | Deliberate limits / future work |
| --- | --- | --- |
| Capture | PCAP/PCAPNG, libpcap, Ethernet/VLAN/IP/TCP/UDP/ICMP, export, conservative BPF hints, tolerant decoding | Automatic hints are Ethernet-only and admit VLAN/IPv6 broadly |
| Flow/analysis | Bounded IP/TCP reconstruction, passive flows, DNS/TLS/HTTP/SSH, idle expiry, affinity workers | Coarse IP-pair affinity favors fragment correctness; initial L7 metadata, no DHCP decoder, no endpoint TCP emulation |
| Recipes | Direct Sucre/Banane/Chocolate/Suzette/Maison/Complete, combined live capture/export, module switches, layered config, serious mode; Suzette retains a forensic case by default | Explicit `--listen` combines packet/export sources; flat TOML rather than the design's nested sketch |
| Queries | Typed packet CQL, richer historical CQL, bounded live windows, hot-tail plus historical queries | Processing-time windows; no event-time retractions or distributed streaming SQL |
| Storage | Arrow/partitioned ZSTD Parquet, atomic imports/checkpoints, crash recovery, copy-based retention/compaction | Retention is an explicit operation into a new store; scheduling/deleting the old copy is operator-controlled |
| Security | Parser/reassembly anomalies, DNS-change notices, bounded indicators/rules, HTTP body SHA-256 | Feeds loaded at startup; exact passive rules; first complete supported Content-Length body |
| Plugins | WIT/API v1, Wasmtime components, manifests/subscriptions, fuel/memory/event limits and tests | No host capabilities/WASI; richer permissioned APIs require a later contract |
| Operations | Daemon, Prometheus, structured logs, systemd, DEB/RPM, archive/license packaging | Linux service-manager behavior depends on local interface/permissions; macOS uses foreground execution |
| Validation | Unit/integration/live tests, adversarial corpus, ASan fuzzing, Criterion, sustained bounded-state/RSS test | Bounded campaigns do not establish multi-day uptime or line-rate behavior on arbitrary hardware |

Core stages 75–84 are represented by runnable implementations and reproducible
checks. The final distribution gate remains tied to the exact tagged commit,
not merely to this table or a version string. The original design's implementation
sketches (file layout, parser library, nested configuration, CLI examples) are
not all literal compatibility requirements; supported alternatives above retain
the functional goals and keep the scope bounded.

## 1.4.0 target-architecture acceptance

The October target's v1 paths now include observed connection identities,
reassembly packet-reference sets, automatic opt-in raw retention/discovery,
CNAME and opt-in cross-source relationships, related timelines, one typed event
predicate AST, composable profile dependency plans and declarative CPL with all
four specified actions. Telemetry/security cutoffs and raw retention are separate.

[Target acceptance](TARGET-ACCEPTANCE.md) maps each requirement to implementation
and tests. [Release 1.4.0](RELEASE-1.4.0.md) records validation. Bounds and unknowns
remain visible: no endpoint emulation, guaranteed capture completeness, clock
alignment inference or unlimited memory. GUI, clustering, decryption and active
blocking remain explicitly outside the target's v1 scope.
