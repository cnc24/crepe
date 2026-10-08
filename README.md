# Crepe

Linux-first network research and analysis in Rust, developed and tested on macOS.
Version 1.2.3 adds `crepe update`, Layer-2 packet output, application-protocol shortcuts,
HTTP summaries/dumps, factual command names with recipe aliases, selected Wireshark
fields, and a flow database/query workflow.
Version 1.2.2 shows one flow per table row; `flows --details` adds expanded counters and state. See the [platform release gates](docs/RELEASE-1.1.md)
and [design choices and limits](docs/DESIGN-STATUS.md).

A modular Cargo workspace covering capture, packet filters, bounded IP/TCP
reassembly, DNS/TLS/HTTP/SSH observations, NetFlow/IPFIX collection and
Arrow/Parquet history queried through DataFusion. Current main also includes
indicator/rule matching, HTTP file hashes, bounded WASM components, a live
sensor daemon, Prometheus counters, parallel affinity workers, bounded live CQL
windows, compressed/partitioned history, crash recovery and native Linux packaging.

**New user? Start with [preparation and installation](docs/GETTING-STARTED.md).**
It covers macOS/Linux prerequisites, installation, your first capture, permissions
and troubleshooting. [Download v1.2.2](https://github.com/cnc24/crepe/releases/tag/v1.2.2)
for Apple Silicon macOS or Linux x86-64; ready-made binaries need no Rust/Cargo.

**[User manual: commands, profiles and troubleshooting](docs/OPERATIONS.md)**

After installing, run these examples from the cloned repository directory:

```sh
crepe read example.pcap 'dst port 443'
crepe analyze fixtures/protocols.pcap
crepe profiles
crepe chocolate fixtures/protocols.pcap
crepe suzette fixtures/dns.pcap --store ./case
crepe ingest fixtures/dns.pcap --store ./history --sensor lab
crepe query ./history 'event.type == flow.end | group proto | sort bytes desc'
crepe collect --listen 127.0.0.1:2055 --duration 30 --store ./history
```

Default builds support offline analysis, storage and UDP flow collection.
`--all-features` additionally enables live libpcap capture (`capture`, alias
`sucre`), offline tcpdump/BPF filters, `interfaces` and sandboxed WASM components. Install `libpcap-dev` on Linux for live builds;
macOS provides libpcap. Live capture needs OS capture permissions.
Rust 1.96+ is required by the current component runtime. CLI errors have stable codes and a
little French humor: *Sacré bleu!* JSON, tables and CSV are supported for
packet/flow/application output; historical queries use JSON Lines.

- [Operations, profiles, limits and recovery](docs/OPERATIONS.md)
- [Schema, IDs and historical CQL](docs/SCHEMA.md)
- [Project architecture](docs/ARCHITECTURE.md)
- [Current release validation](docs/RELEASE-1.2.md)
- [Platform release acceptance](docs/RELEASE-1.1.md)
- [Validation record](docs/VALIDATION.md)
- [Measured comparison with Zeek/SiLK and command examples](docs/COMPARISON.md)
- [Tested tcpdump/nfpcapd/nfdump workflows and filters](docs/PACKET-FLOW-COMPARISON.md)

This is a passive research platform. TLS analysis reads cleartext handshake
metadata; HTTP/SSH support covers initial headers/banners. It does not decrypt
traffic, recover missing capture bytes, block network traffic or provide a
web interface. See the documented per-engine limits before interpreting an
incomplete capture. Synthetic fixtures contain no user network traffic.

The current development tree uses the [Crepe Source Available License 1.0](LICENSE).
Personal use and internal company use are free. Embedding in paid products,
reselling, or providing paid hosted/managed analysis requires a separate written
commercial license. This is source-available, not OSI open source.
See [licensing examples](docs/LICENSING.md).
This repository starts with a clean source-available history.
