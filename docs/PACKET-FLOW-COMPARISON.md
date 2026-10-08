# Crepe, tcpdump, nfpcapd and nfdump

Tested locally on 2026-10-05, Apple Silicon/macOS 27: Crepe 1.2.0,
tcpdump 4.99.1 (Apple 161, libpcap 1.10.1), nfpcapd and nfdump 1.7.10.
All **43 functional checks passed**. These are correctness/usage checks on
synthetic captures, not throughput benchmarks or a claim of complete parity.
[Machine-readable results](benchmarks/2026-10-05-packet-flow.json).

## Choose the workflow

| Task | Crepe | Other tool |
| --- | --- | --- |
| Read packets for HTTPS | `crepe read traffic.pcap 'dst port 443'` | `tcpdump -nn -S -r traffic.pcap 'dst port 443'` |
| Read UDP DNS | `crepe read traffic.pcap 'udp port 53'` | `tcpdump -nn -r traffic.pcap 'udp port 53'` |
| Live packet view | `crepe capture -i en0 'port 443'` | `tcpdump -nn -i en0 'port 443'` |
| Build and display flows from PCAP | `crepe flows traffic.pcap` | `mkdir flows; nfpcapd -r traffic.pcap -w flows`, then `nfdump -R flows` |
| Select both HTTPS directions from PCAP | `crepe flows traffic.pcap 'port 443'` | `nfpcapd -r traffic.pcap -w flows 'port 443'`, then `nfdump -R flows` |
| Select existing stored flow records | `crepe query ./case 'event.type == flow.end && dst.port == 443'` | `nfdump -R flows 'dst port 443'` |
| Machine-readable flows | `crepe flows traffic.pcap --format json` | `nfdump -R flows -q -N -o ndjson` |
| Application analysis | `crepe chocolate traffic.pcap` | Separate workflow; nfdump is primarily a flow analysis suite |

Use an actual interface from `crepe interfaces`. Live packet capture needs OS
capture permissions; the file examples above do not. Create a **fresh** output
directory for each nfpcapd example. `capture` defaults to 30 seconds; tcpdump
runs until interrupted unless you give it another stopping condition.

`nfpcapd` converts packets into nfdump flow files. `nfdump` reads those files;
its `-r` is not a general PCAP input option. NetFlow/IPFIX exporters normally
send to **nfcapd**, which is a different collector from **nfpcapd**. Crepe's
corresponding exporter collector is `crepe collect` / `crepe banane`.
See the [upstream suite description](https://github.com/phaag/nfdump/tree/v1.7.10).

## Filters are related, but not one universal language

- `tcpdump`, `nfpcapd` and Crepe's BPF packet path use libpcap filter syntax:
  `dst port 443`, `src host 192.0.2.10`, `udp and port 53`.
- `nfdump` has its own **flow** filter language. Common expressions such as
  `dst port 443` overlap, but flow predicates such as `packets > 10` do not
  become BPF packet predicates. Crepe does not claim to parse the entire
  nfdump language or read nfdump's binary storage format.
- Crepe's packet CQL is also available: `dst.port == 443`. It is not the full
  Wireshark language. `--filter-syntax auto|cql|bpf` selects packet parsing.
- Stored Crepe observations use historical CQL, including counts/aggregation:
  `crepe query ./case 'event.type == flow.end && packets > 10 | count'`.

`crepe flows ... FILTER` applies its predicate **before** building flows;
`nfdump ... FILTER` selects already-built flow records. These operations agree
for the tested direction-level endpoint predicates after normalizing counters,
but are not interchangeable for time, payload or packet-state predicates.
Crepe history stores canonical conversation endpoints for packet-derived flows;
`src`/`dst` there should not be assumed to mean first initiator/responder.
The [operations reference](OPERATIONS.md#command-and-filter-quick-reference)
lists the supported commands and grammars.

## What matched locally

1. **32 filter selections**: eight expressions across four supplied PCAP/PCAPNG
   inputs. The test lets tcpdump export selected packets, decodes that export,
   and compares full Crepe packet records (excluding renumbered sequence).
   Expressions cover TCP, UDP DNS, destination port, source subnet, IPv6,
   TCP SYN bit arithmetic, frame length and port ranges.
2. **Three summary checks**: displayed TCP SYN/ACK/FIN/RST flags, window and
   payload length; UTC timestamp; DNS question name and response presence.
3. **Eight flow checks**: packets and IP bytes for the small flow fixture and
   a generated 20,000-packet/1,000-conversation dataset; three matching
   direction-level filters on each dataset.

The small fixture contains **8 packets / 296 IP bytes**. Crepe emits three
bidirectional records; nfpcapd/nfdump emit five directional records.
The generated dataset contains **20,000 packets / 880,000 IP bytes**.
Different record counts are not automatically packet loss: direction and flow
expiration policies can split conversations differently.

Crepe's packet-derived byte counters include link headers. nfpcapd's counters
in this test are IP bytes. The comparator subtracts **14 Ethernet bytes per
packet** from Crepe's values before comparing. That normalization is specific
to these untagged Ethernet fixtures; do not apply it blindly to VLAN, loopback
or raw-IP captures. Existing NetFlow/IPFIX counters retain the exporter's units.

## Packet presentation

Crepe's default packet view now uses UTC clock time, a source-to-destination
arrow, TCP flags, absolute sequence/ACK numbers, unscaled window, TCP options,
payload length, frame length, ICMP labels and compact UDP DNS summaries.
For a comparable tcpdump view use `TZ=UTC tcpdump -nn -S -r FILE FILTER`.
Without `-S`, tcpdump normally presents relative TCP sequence numbers; without
`-nn`, it may resolve host/service names. Crepe does neither in the packet view.
IP JSON retains its lossless timestamp/schema. Since 1.2.3 packet CSV appends four link fields; see the manual.

This is not a byte-for-byte clone of tcpdump output. tcpdump decodes more link
and application protocols. Crepe's compact UDP/53 summary shows DNS questions
and answer counts; use `analyze` or `chocolate` for full DNS resource records,
TCP reassembly and HTTP/TLS observations. See the operations manual for BPF
build requirements, truncated-frame restrictions and timestamp details.

## Reproduce

Install the comparison tools separately; they are **not** Crepe runtime
requirements and are not bundled in releases. Homebrew's nfdump 1.7.10 package
on this test Mac includes nfdump but not nfpcapd. nfpcapd was built from the
unmodified upstream v1.7.10 source with `--enable-nfpcapd`; the macOS 27 SDK
requires `ac_cv_header_fts_h=no` (also used by Homebrew's nfdump formula).
Source tarball SHA-256:
`9a1bc84eb484c7383eea3b48ad2abe5b9ffe7e90aab3fda7055aa3f64be0cc29`.
Build commands after installing upstream's compiler/autotools prerequisites:

```sh
./autogen.sh
ac_cv_header_fts_h=no ./configure --enable-nfpcapd --prefix="$PWD/local" LEXLIB=
make -j4
make install
```

The `ac_cv_header_fts_h` workaround is specific to this Mac SDK, not a required
Linux setting. The upstream [nfpcapd manual](https://github.com/phaag/nfdump/blob/v1.7.10/man/nfpcapd.1)
documents its input and capture options.

From the Crepe checkout, with an all-features release build:

```sh
python3 scripts/compare-packet-tools.py \
  --crepe target/release/crepe \
  --nfpcapd /absolute/path/to/nfpcapd \
  --output /tmp/crepe-packet-comparison-new
```

The script refuses to overwrite an existing output directory. It saves exact
commands, stdout/stderr, generated captures, nfdump flow files and a result JSON.
It uses only synthetic file input, no privileged/live capture, and does not
install tools. No latency, memory or speed ranking is inferred from this run.
For the separately measured Zeek/SiLK comparison, see [COMPARISON.md](COMPARISON.md).
