# Crepe, Zeek and SiLK: measured comparison and command guide

Tested locally on 2026-10-04 on an Apple M2 Pro with 16 GiB RAM, macOS 27.0
(26A428), native arm64 tools. Crepe 1.1.0 at `8a201bc`, Zeek 9.0.0 (Homebrew),
and SiLK 3.24.2 (native source build). The comparison script and this report
are later additions; no analyzer changes were made to obtain these results.

**Finding:** Crepe's dedicated flow command used less time and memory on these
synthetic UDP captures. SiLK used much less memory for historical queries and
was faster on the larger query. The results do not establish a generally faster,
safer or more capable product. Ease of use was inspected through equivalent
commands, not measured in a user study.

## What was checked

Both dataset sizes passed all 11 checks:

1. TLS ClientHello SNI `example.test` in Crepe and Zeek.
2. HTTP GET, host `example.test`, URI `/research` in both.
3. SSH identification `SSH-2.0-CrepeFixture` in both.
4. DNS question `example.test` in both (trailing dot normalized).
5. DNS answer `203.0.113.7` in both.
6. Conversation packet counts and normalized IP-byte counts in the small flow fixture.
7. Generated UDP conversation counts, packet counts and normalized IP bytes match
   between Crepe and default Zeek and match the generator's expected flow/packet counts.
8. The same generated-flow equality holds for Zeek with only connection logging loaded.
9. SiLK preserves all generated NetFlow v5 source/destination ports, protocol,
   packet counts and byte counts.
10. Crepe preserves those same NetFlow v5 fields after UDP collection and storage.
11. Historical filtering on destination port 443 and summing bytes by protocol
    agrees between Crepe, SiLK and the generator's expected sum.

The timed PCAP workloads contain 200,000 packets/10,000 conversations and
1,000,000 packets/40,000 conversations. They are simple IPv4 UDP exchanges between
two hosts with distinct source ports, no loss and no fragmentation. Packet times
span 2 and 10 seconds respectively. This stays within configured flow limits.
The flow comparison subtracts the 14-byte Ethernet header from Crepe's wire-byte
counters to compare against Zeek's IP-byte counters. That conversion applies only
to these untagged Ethernet fixtures, not arbitrary link types or VLAN captures.

The NetFlow tests use 3,000 and 10,000 generated records. Crepe receives the UDP
PDUs; SiLK reads the identical PDUs padded to its documented 1,464-byte file
format. Ingestion is validated, but **not included in the query timing**. SiLK
was built without libfixbuf; this comparison tests NetFlow v5, not SiLK's optional
IPFIX/NetFlow v9 ingestion. No YAF installation or SiLK packet-to-flow benchmark
was performed.

The small protocol/fragment fixtures are handcrafted. Their minimal TCP ACK
values cause Zeek `bad_SYN_ack` / `TCP_ack_underflow_or_misorder` notices. These
are fixture limitations, not Zeek failures. Matching selected extracted fields
does not establish identical TCP reconstruction or malformed-traffic handling.
For example, Crepe emits separate DNS query/response observations, while Zeek
normally produces a transaction log: five Crepe DNS events versus three Zeek DNS
rows in the DNS fixture is not evidence of missed traffic. The IPv4/IPv6 fragment
fixture produced two DNS query observations in Crepe and two DNS log rows in Zeek.

## Timing and memory

One warmup per command, then five measured runs in a seeded mixed order.
Wall time includes process startup and writing output to local files. File/page
caches were not flushed; this is a normal desktop, not an isolated benchmark host.
RSS is measured freshly for each process via `wait4`, not a cumulative maximum
across earlier subprocesses. Memory values below are medians of the five process
peaks in MiB (1,048,576 bytes).

| Task | Tool/configuration | Median seconds | Min–max seconds | Median peak MiB |
| --- | --- | ---: | ---: | ---: |
| 200k packets, 10k flows | Crepe `flows` | 0.142 | 0.139–0.189 | 29.3 |
| Same capture | Zeek default scripts | 0.762 | 0.619–0.847 | 248.9 |
| Same capture | Zeek bare + connection logging | 0.562 | 0.525–0.730 | 191.6 |
| 1m packets, 40k flows | Crepe `flows` | 0.680 | 0.647–0.782 | 59.1 |
| Same capture | Zeek default scripts | 1.773 | 1.668–2.695 | 616.4 |
| Same capture | Zeek bare + connection logging | 1.364 | 1.307–4.178 | 492.6 |
| Filter/sum, 3k stored records | Crepe CQL/Parquet | 0.016 | 0.015–0.028 | 40.6 |
| Same logical query | SiLK filter + aggregate | 0.018 | 0.015–0.022 | 11.4 |
| Filter/sum, 10k stored records | Crepe CQL/Parquet | 0.033 | 0.019–0.060 | 42.5 |
| Same logical query | SiLK filter + aggregate | 0.016 | 0.016–0.033 | 11.6 |

Zeek's default scripts do more work than Crepe `flows`. Bare Zeek with
`base/protocols/conn` narrows that gap, but does not make their engines, checksum
handling or output schemas identical. SiLK query time is the sum of two sequential
processes and includes writing their intermediate flow file; its reported RSS is
the larger process peak, not the sum. A pipe-based SiLK workflow could behave
differently. Storage formats/compression/partition layouts differ. The 3k/10k
queries are small and startup-sensitive, not a test of large historical archives.

Raw samples, exact versions, input hashes and check results:
[small dataset](benchmarks/2026-10-04-small.json),
[larger dataset](benchmarks/2026-10-04-large.json).

## The actual commands and parameters

Commands below use short example paths in place of the runner's absolute paths.
Crepe's ordinary analysis output goes to the terminal; Zeek writes protocol logs
into the working directory. The comparison runner preserves those outputs in
separate directories for each run.

### Extract protocol information from a PCAP

Crepe:

```sh
crepe analyze capture.pcap --format json
```

Zeek:

```sh
zeek -r capture.pcap LogAscii::use_json=T
```

| Parameter | Meaning |
| --- | --- |
| Crepe `analyze` | Run DNS/TLS/HTTP/SSH analysis after bounded reconstruction. |
| Crepe `--format json` | Emit JSON Lines observations to stdout. |
| Zeek `-r` | Read this capture file instead of a live interface. |
| Zeek `LogAscii::use_json=T` | Configure JSON logs instead of the default text log format. |

Both take one command. Zeek's `dns.log`, `http.log`, `ssl.log` and `ssh.log` are
usefully separated by protocol; Crepe emits a shared event stream. **There is no
clear command-count advantage for Crepe on this task.** Crepe's interactive
`crepe choclate` adds an explanation and source menu for users who do not already
know which input parameter to supply. The timed protocol comparison uses
`analyze`, not `choclate`, which follows a different ingestion/output path.

### Extract conversations and counters

Crepe:

```sh
crepe flows udp.pcap --format json
```

Zeek default:

```sh
zeek -r udp.pcap LogAscii::use_json=T
```

Zeek restricted to connection logging:

```sh
zeek -b -r udp.pcap base/protocols/conn LogAscii::use_json=T
```

Zeek `-b` skips the default base scripts; `base/protocols/conn` explicitly loads
connection logging. These paths/scripts are part of Zeek's configuration model.
Crepe makes the narrower task explicit through the `flows` subcommand. Neither
command needs a separate historical database for this task.

### Import router flow data

The test starts Crepe with:

```sh
crepe collect --listen 127.0.0.1:0 --duration 30 --count 100 --store ./history
```

`--listen ...:0` asks the OS for a free UDP port; the test reads the chosen port
from stderr and sends exactly 100 datagrams for the 3,000-record case.
`--count` counts datagrams, not exported flow records. A human normally uses a
fixed port, such as `crepe banane --listen 0.0.0.0:2055 --store ./history`, and
configures the exporter and firewall accordingly. `banane` is the collector alias.

SiLK's tested file import is:

```sh
rwpdu2silk --silk-output=exports.rw exports.pdu
```

This reads a saved, padded NetFlow v5 PDU file. It is **not** a replacement for
SiLK's live collector setup. The two import commands have different input
transports; no ingestion performance comparison is claimed.

### Filter stored flows and sum bytes by protocol

Crepe:

```sh
crepe query ./history 'event.type == flow.export && dst.port == 443 | group proto | sum bytes as total'
```

SiLK (the measured two-step workflow):

```sh
rwfilter --dport=443 --pass=selected.rw exports.rw
rwuniq --fields=protocol --values=bytes --no-titles --delimited=, --sort-output selected.rw
```

Use a fresh `selected.rw` path for each repetition: SiLK protects existing output
files from accidental overwrite. The benchmark does not disable that protection.

| Crepe expression | SiLK option | Purpose |
| --- | --- | --- |
| `event.type == flow.export` | Input file already contains only flow records | Select the relevant event kind in Crepe's mixed store. |
| `dst.port == 443` | `--dport=443` | Select HTTPS-port destinations; this does not prove the traffic is HTTPS. |
| `group proto` | `--fields=protocol` | Group by transport protocol. |
| `sum bytes as total` | `--values=bytes` | Add byte counters. |
| Built-in JSON output | `--no-titles --delimited=,` | Output formatting; SiLK returns delimited text here. |
| Not needed for one group | `--sort-output` | Stable SiLK output order. |
| Integrated query stages | `--pass=selected.rw` | Transfer filtered records to the aggregation step. |

Crepe combines filtering and aggregation in one expression and queries the same
store used by other event types. SiLK uses a composable tool pipeline. Crepe's
advantage here is fewer separate steps, but its CQL is still a language users
must learn. Advanced SiLK users may prefer the explicit pipeline. No novice
completion-time or error-rate study has been performed.

## Reproduce

Install native Zeek and SiLK outside the Crepe repository. They are test tools,
not Crepe dependencies, and their code/binaries are not redistributed here.
Zeek was installed using `brew install zeek`. SiLK was downloaded from the
[official download page](https://tools.netsa.cert.org/silk/download.html), version
3.24.2, SHA-256
`9ea9c1391f9c1ba14394af68b2bd7e66bf73b664c3cee342c5a39e5b13e45398`, and built with
`./configure --prefix=/absolute/test/silk --enable-ipv6 --without-libfixbuf --without-python`,
then `make -j4` and `make install`. Choose a user-writable prefix.

From Crepe's repository root, after building the release executable:

```sh
python3 scripts/compare-tools.py --silk-bin /absolute/test/silk/bin --output /tmp/crepe-compare-small
python3 scripts/compare-tools.py --silk-bin /absolute/test/silk/bin --output /tmp/crepe-compare-large --flows 40000 --packets-per-flow 25 --export-records 10000
```

Output directories must not already exist. Each contains generated input files,
raw tool output, measured commands and `results.json`. The script uses only
Python's standard library, captures subprocesses' individual resource usage,
and checks correctness before interpreting timings. No real user traffic is used.
A low-level packet generator is shared with the repository's fixtures; the test
therefore complements, but does not replace, independent captures and datasets.

Still untested: sustained high-rate live capture, packet loss under overload,
multi-day stability, large archives, diverse real-world/encrypted traffic,
distributed deployments, the full protocol/rule surface, and user-study evidence
for an intuition/ease-of-use advantage. Rust is not itself evidence of superiority.

References: [Zeek overview](https://docs.zeek.org/en/current/about/what.html),
[SiLK overview](https://tools.netsa.cert.org/silk/silk.html),
[SiLK PDU format](https://tools.netsa.cert.org/silk/rwpdu2silk.html).
