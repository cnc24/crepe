# Crepe 1.1 release gates

Version 1.1.0 is the initial source-available publication candidate. Private
prototype history and binaries are excluded from this repository. This document
defines the supported release contract; the original design is a planning
source, not a promise of every illustrative syntax or future extension.

| Gate | Implementation and validation |
| --- | --- |
| Stable CLI and schemas | Existing commands retained; direct recipes, stable errors, serious/JSON diagnostics, documented packet/application/history contracts |
| Query DSL | Typed packet filters; closed historical CQL with protocol fields, units, CIDR/port lists, aggregates and bounded live processing windows; parser/integration tests |
| Network analysis | Capture, flow state, bounded IP/TCP reconstruction, DNS/TLS/HTTP/SSH, file SHA-256; real local servers and malformed/synthetic fixtures |
| Export collection | v5/v9/IPFIX, templates/options/sampling/sequence notices; combined capture/export into one store; actual UDP smoke tests |
| Security | Bounded offline IP/domain/CIDR/hash indicators and observational policy rules, correlated notices; unit and persistence tests |
| Component API v1 | WIT export, strict manifests, no host imports/WASI, resource budgets, bundle path confinement; trap/fuel/memory/permission/path tests |
| Parallelism and pressure | 1–16 bounded live workers with bidirectional/fragment affinity; serial/parallel parity and failed-sink shutdown tests; sustained pressure/RSS check |
| Storage and recovery | Schema 1, partitioned ZSTD Parquet, atomic imports/checkpoints, bounded hot/cold query snapshots, copy-based retention/compaction; concurrent rotation and real SIGKILL/restart tests |
| Operations | Foreground daemon, systemd unit, loopback Prometheus, SIGINT/SIGTERM shutdown, explicit limits/recovery/upgrade manual |
| Distribution and licenses | Deterministic archives, native DEB/RPM scripts, dependency/runtime notices and inventory; package checks and native install validation |
| Hardening | Formatting, strict Clippy, default/all-feature tests, release builds, instrumented fuzzing, Criterion and real local capture/collector/service checks |

The final tagged revision must pass Linux/macOS CI and the Fedora RPM job before
assets are published. Earlier private development checks do not replace this
publication candidate's own CI.
The final release notes identify the exact accepted commit and CI run.

Supported limits are in OPERATIONS.md and SCHEMA.md. These include initial
HTTP/TLS/SSH metadata, first supported HTTP body hashing, passive TCP semantics,
processing-time windows, explicit copy-based retention and zero-capability
components. Event-time watermarks/retractions, automatic retention scheduling,
HTTP/2/QUIC, TLS decryption, active blocking, distributed coordination and a web
UI are not promised by this release. The latter protocol/distributed/UI work is
also explicitly listed after 1.0 in the original design.
