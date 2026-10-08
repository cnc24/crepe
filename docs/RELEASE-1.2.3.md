# Crepe 1.2.3 acceptance notes

Validated locally on macOS ARM64, 8 October 2026. See
[Operations](OPERATIONS.md) for the command/alias table, exact filter subset,
flow-store workflow and update instructions.

## Changes you can try

```sh
crepe read http.pcap http -vvX
crepe read http.pcap 'ip.src == 10.0.0.5'
crepe read fixtures/packet-display.pcap arp
crepe flows fixtures/flows.pcap --store ./flow-history
crepe flows ./flow-history '* | sort packets desc | limit 10'
crepe query ./flow-history '* | sort bytes desc | limit 10'
crepe flows fixtures/flows.pcap --group src.ip,dst.ip --sort flows
crepe flows fixtures/flows.pcap --count
crepe flows -h
crepe update --check
```

`flows --store` creates durable Parquet history, readable by both `flows` and
`query`. Without `--store`, a query over a capture uses temporary history.
Explicit `--query` filters the resulting flow records; a packet filter before
aggregation can change the counters. Flow-only imports contain no DNS/TLS
observations; use `forensics` (alias `suzette`) for a fuller case and `trace` for
conversation correlation. This is not an arbitrary join language.

## Local verification

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo test --workspace --locked`: 115 passed.
- `cargo test --workspace --all-features --locked`: 121 passed.
- `cargo build --release --all-features --locked`
- Architecture and dependency-license checks passed.
- Loopback capture/replay, DNS, recipes, service shutdown/metrics and full
  platform smoke scripts passed, including local HTTP/SSH/TLS traffic and
  NetFlow v5/v9/IPFIX collection into history.
- Update integration tests cover check-only, verified staged installation,
  version checking, checksum mismatch and preservation of existing files.
  Actual `update --check` also reached the official GitHub API successfully.

The tests compare direct flow queries against queries over the same durable
store, including counts, packet/byte sorting, endpoint grouping and correlation
IDs. Packet tests cover combined `-vvX`, link-inclusive `-XX`, ARP/VLAN output,
export/replay, terminal escape handling and protocol-qualified field aliases.

## Comparisons with other tools

`scripts/compare-cli-compatibility.py` passed **50/50** checks using TShark
4.6.9 and tcpdump 4.99.1. It compares selected frame numbers for twelve filters
across four captures, plus HTTP request details and verbose IP output.
The external HTTP sample was Wireshark's
[`test/captures/http.pcap`](https://github.com/wireshark/wireshark/blob/master/test/captures/http.pcap),
SHA-256 `69e489a26a59208a1dd56fbea4c606b1e59e8ac32d3d4789ca6cc81e71bad3f2`.
It contains a HEAD request; the generated repository fixture additionally
covers requests/responses on port 8088, binary bytes and link-layer traffic.
The external capture is not redistributed here.

```sh
python3 scripts/compare-cli-compatibility.py --output comparison-new \
  --tshark /path/to/tshark --http-capture /path/to/http.pcap
python3 scripts/compare-packet-tools.py --output flow-comparison-new \
  --nfpcapd /path/to/nfpcapd
```

The second script passed **43/43** checks with tcpdump 4.99.1 and
nfdump/nfpcapd 1.7.10. It compares BPF selections, TCP/DNS summaries and
direction-normalized packet/IP-byte counts, including 20,000 generated packets
across 1,000 conversations. Crepe's bidirectional rows and frame-byte totals
are deliberately distinguished from nfdump's directional rows and IP-byte totals.

These are functional comparisons on the listed inputs, not a claim of complete
compatibility or a performance ranking. Crepe does not implement every TShark
dissector/display field or every nfdump statistic. The `http` packet filter is
packet-local: headerless continuation segments, encrypted HTTP and HTTP/2 do
not become HTTP/1 request lines. `-A`/`-X` expose packet bytes; stream analysis
belongs to `analyze`/`inspect`/`forensics`.

Implementation and documentation were checked against the official
[tcpdump manual](https://www.tcpdump.org/manpages/tcpdump.1.html),
[TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html),
[Wireshark filter manual](https://www.wireshark.org/docs/man-pages/wireshark-filter.html)
and [nfdump manual](https://github.com/phaag/nfdump/blob/master/man/nfdump.1).

## Upgrade and compatibility

Versions through 1.2.2 have no self-updater. Install 1.2.3 once using the release
archive/package. Standalone archive installations can subsequently use
`crepe update`; package-manager/Cargo installations use their installer instead.
The updater checks SHA-256 against both the manifest and GitHub asset digest,
then stages and atomically replaces the binary. This is not a detached signature.
`crepe licenses` retains license notices inside a self-updated binary.

Root help lists factual commands and recipe aliases in separate columns.
Existing aliases remain accepted. Packet CSV appends four link columns;
non-IP JSON has MAC/link fields instead of invented IP endpoints. Existing IP
JSON and flow/history schemas remain unchanged. The correct French interjection
is **Zut alors!**, as listed by
[Larousse](https://www.larousse.fr/dictionnaires/francais-anglais/zut/82254).
