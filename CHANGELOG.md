# Changelog

## 1.2.2 — 2026-10-05

- Restore Suzette’s forensic workflow: automatically retain a case unless a store is explicitly selected, and show statistics/timeline/trace commands. Other offline recipes remain temporary by default.

- Fix Linux `capture -i any` on loopback traffic (SLL/ARPHRD_LOOPBACK); test live ICMP capture and replay on Linux.
- Accept `interface` as an alias for `interfaces`.
- Keep help factual, explain recipe workflows and Suzette's current behavior.
- Report file-analysis startup and periodic record progress on stderr; explain empty results and live waiting. JSON data stays clean.

- Correct the default flow presentation to one aligned row per bidirectional flow,
  with UTC start, clock-style duration, endpoints and exact total counters.
- Keep expanded directional flags/state/end reasons behind `flows --details`.
  Packet (`read`) output and flow JSON/CSV remain unchanged.
- Document differences between Crepe bidirectional records and nfdump's common
  directional records; do not silently change flow accounting to match a layout.

## 1.2.1 — 2026-10-05

- Replace the wide flow table with 80-column wrapped summaries: UTC date/time,
  duration, bidirectional endpoints, exact packet/frame-byte counters, cumulative
  TCP flags and readable end reasons/passive state. JSON and CSV stay unchanged.
- Explain direction, file-end versus connection-close, and flow IDs in the manual.

## 1.2.0 — 2026-10-05

- Correct the canonical recipe name to `chocolate`; retain `choclate` as a CLI,
  profile-option and configuration alias.
- Accept tcpdump/libpcap BPF filters in `read`, `flows` and `capture`, with explicit
  grammar selection and unchanged CQL support. Official binaries include BPF;
  portable builds without `live` explain how to enable it.
- Show UTC time, packet direction, TCP flags/absolute seq/ack/window/options,
  payload/frame lengths, ICMP descriptions and UDP DNS summaries in packet view.
  JSON/CSV packet schemas remain unchanged.
- Add command/filter documentation and reproducible tcpdump/nfdump/nfpcapd checks.

## 1.1.0 — follow-up documentation and usability

- Explain each interactive analysis recipe before source selection, with optional
  French/culinary flair and a factual `--serious` presentation.

- Add a complete end-user setup guide for macOS, Ubuntu/Debian and Fedora,
  including prerequisites, installation, capture permissions and troubleshooting.

- Rename the deep-analysis recipe and profile to `choclate` (corrected to
  `chocolate` in 1.2.0), including CLI, configuration and documentation.

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
