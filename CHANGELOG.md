# Changelog

## Unreleased

- Add a complete end-user setup guide for macOS, Ubuntu/Debian and Fedora,
  including prerequisites, installation, capture permissions and troubleshooting.

- Rename the deep-analysis recipe and profile to `choclate`, including CLI,
  configuration values, examples and documentation. Update existing profile
  configurations to use `profile = "choclate"`.

## 1.1.0 — initial source-available candidate

- Initial publication snapshot under Crepe Source Available License 1.0.
  Internal company use is free; paid embedding, resale and hosted/managed
  analysis require a separate commercial agreement.

- Complete continuous live analysis with bounded parallel workers, combined
  packet/NetFlow/IPFIX ingestion, live CQL windows and hot/historical queries.
- Add offline indicators/policies, correlated notices, HTTP file SHA-256 and
  isolated WASM components with explicit resource and path limits.
- Add layered configuration, module selection, serious/JSON diagnostics,
  tolerant packet decoding and conservative Ethernet BPF hints.
- Add partitioned ZSTD history, durable live checkpoints, OS-lock crash recovery,
  copy-based compaction/retention, foreground daemon, Prometheus and systemd.
- Add native DEB/RPM packaging, complete dependency/runtime license bundles,
  component/adversarial tests, sustained pressure tests and Criterion benchmarks.
- Support schema 1 history and the documented commands.
  Legacy PID-only locks need the documented one-time upgrade check.
