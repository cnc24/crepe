# Operating Crepe

New users: follow [Getting started](GETTING-STARTED.md) for OS preparation,
installation, PATH setup, capture permissions and a first working example.

## Command and filter quick reference

Examples below use the included synthetic captures. For a real capture replace
`example.pcap` with your file. Put filters in single quotes so the shell does not
interpret parentheses, `!`, `&` or `|`. `[]` below means optional arguments.
Every command supports `--help`.

| Command | What it does / common options |
| --- | --- |
| `read FILE [FILTER]` | Packet summaries; `--format table\|json\|csv`, `--limit N`, `--write FILE`, `--tolerant`, `--filter-syntax auto\|cql\|bpf` |
| `capture -i IFACE [FILTER]` / `sucre` | Live packet summaries; read options plus `--duration SECONDS`, `--count N`, `--bpf FILTER`, `--promisc` |
| `interfaces` | List available capture interfaces |
| `flows FILE [FILTER]` | Bidirectional TCP/UDP counters; `--details`, `--format`, `--filter-syntax`, `--max-flows`, `--tcp-idle`, `--udp-idle`, `--active-timeout` |
| `analyze FILE` | Reassembly and application observations; `--format table\|json\|csv`, `--dns-port`, `--max-streams`, `--max-buffer-bytes`, `--stream-idle` |
| `chocolate [FILE]` | Deep-analysis recipe; without a source, opens the interactive menu |
| `suzette [FILE]` | Forensic-analysis recipe |
| `maison [FILE] --config FILE` | Analysis using your own configuration |
| `complete [FILE]` | All implemented observation modules |
| `profiles` | List recipes and descriptions |
| `ingest FILE --store DIR` | Import into persistent history; `--profile`, `--sensor`, `--config` |
| `query DIR [CQL]` | Query stored observations; default `*`, JSON Lines output |
| `trace DIR FLOW_ID` | Stored observations for a conversation |
| `timeline DIR --limit N` | Chronological stored observations |
| `collect` / `banane` | Receive NetFlow v5/v9/IPFIX; `--listen IP:PORT`, `--duration SECONDS`, `--count N`, `--store DIR`, `--sensor NAME` |
| `config [FILE]` | Validate and show effective configuration |
| `daemon --config FILE` | Configured live sensor; optional `--duration SECONDS` |
| `compact DIR --output NEW_DIR` | Copy/compact a stopped history store; optional `--since-ms UNIX_MS` |

The four analysis recipes share `-i IFACE` (instead of FILE), `--duration`,
`--store`, `--config`, `--enable MODULE`, `--disable MODULE`, `--tolerant` and
`--workers 1..16`. Live recipes additionally accept `--listen IP:PORT`,
`--query CQL` and `--query-interval SECONDS`. Recipe output is observation JSON
Lines, not the packet summary; use `read`/`capture` for the packet view.
`choclate` remains a compatibility alias; use **`chocolate`** in new commands and
`profile = "chocolate"` in configurations.

Global options: `--serious` removes humorous diagnostics, `--log-format json`
changes diagnostics on stderr, `--metrics IP:PORT` enables the metrics endpoint,
`--version` shows the installed version. `--format json` controls data on stdout
and is independent of `--log-format`. Formats are not interchangeable schemas:
packet records, flow records and historical observations have different fields.

### Packet filters: tcpdump/BPF or CQL

`read`, `capture`/`sucre` and `flows` accept either grammar in the same positional
argument. Official release binaries include libpcap support. A portable source
build without the `live` feature supports CQL only; build with `--features live`
or `--all-features` for BPF. Reading a file does not require capture privileges.

| Task | tcpdump/BPF | Crepe packet CQL |
| --- | --- | --- |
| Destination HTTPS port | `dst port 443` | `dst.port == 443` |
| TCP only | `tcp` | `proto == tcp` |
| UDP DNS | `udp and port 53` | `proto == udp && (src.port == 53 || dst.port == 53)` |
| Source address | `src host 192.0.2.10` | `src.ip == 192.0.2.10` |
| Source subnet | `src net 192.0.2.0/24` | `src.ip in 192.0.2.0/24` |
| Two destination ports | `dst port 80 or dst port 443` | `dst.port in [80,443]` |
| Exclude DNS destination | `not dst port 53` | `dst.port != 53` |
| TCP SYN bit | `tcp[tcpflags] & tcp-syn != 0` | Not available in packet CQL |

```sh
crepe read example.pcap 'dst port 443'
crepe read fixtures/dns.pcap 'udp and port 53'
crepe read example.pcap 'dst.port == 443' --format json
crepe read example.pcap 'tcp[tcpflags] & tcp-syn != 0' --filter-syntax bpf
crepe flows fixtures/flows.pcap 'tcp' --format csv
crepe capture -i lo0 'udp port 53' --duration 10
# Linux loopback is usually lo; list interfaces before choosing one.
```

Auto mode recognizes CQL's dotted endpoint fields and `proto ==` / `proto !=`;
other expressions go to libpcap. Use `--filter-syntax cql` or `bpf` to force a
grammar when needed. This is Crepe CQL, **not full Wireshark display-filter
syntax**. Packet CQL fields are exactly `src.ip`, `dst.ip`, `src.port`,
`dst.port`, `proto`; operators are `==`, `!=`, `&&`, `||`, `!`, parentheses,
IP `in CIDR` and port `in [N,...]`. Protocols: `tcp`, `udp`, `icmp`, `icmpv6`
or a numeric IP protocol. No payload strings or history pipelines here.

BPF uses the actual libpcap compiler, including its `host`, `net`, `port`,
`portrange`, protocol, boolean and packet-byte expressions. Consult
[pcap-filter(7)](https://www.tcpdump.org/manpages/pcap-filter.7.html) for grammar
and link-layer/IPv6 qualifications. Names in BPF expressions may be resolved by
libpcap; use numeric addresses for reproducibility. Packet output itself never
performs reverse DNS or service-name lookups.

Limits: BPF filters are bounded to 4096 bytes and validated for Ethernet first,
then compiled for each encountered supported linktype. Ethernet-only expressions
can fail on raw-IP/loopback inputs. This version explicitly rejects snaplen-truncated
frames with `CREPE-CAP-005` on the userspace BPF path: the safe binding cannot
preserve the original wire length for `len`/`greater`/`less`. Capture full frames,
or use CQL with `--tolerant` to skip malformed packet payloads. `read` still
emits only supported IP packets: an ARP filter does not make it an ARP decoder.
BPF port filters and CQL differ for fragments, VLANs and IPv6 extension headers;
BPF follows libpcap's semantics. Do not assume every superficially equivalent
expression selects every edge case identically.

`flows` filters packets **before** aggregation: `dst port 443` excludes reverse
packets, so counters cover only that direction. Use `port 443` for both directions.
The positional capture filter runs in userspace; `--bpf` is a separate kernel
prefilter and intersects it. CQL may supply a conservative automatic prefilter.
`--count` counts delivered records before the userspace filter; `--limit` counts
matching printed packets.

### Reading the packet summary

```text
22:13:20.123456000Z IP 192.0.2.10:50000 > 198.51.100.20:443: TCP Flags [S], seq 1, win 65535, length 0, wire 54 bytes
22:13:20.123456000Z IP 192.0.2.10:53000 > 198.51.100.20:53: UDP, length 30, DNS query id 4660 rcode 0 A "example.test.", wire 72 bytes
```

Time is UTC (`Z`), to nanoseconds, with the date omitted like tcpdump's default.
The digits reflect capture precision; they do not imply nanosecond accuracy.
Untimed PCAPNG packets say `time unknown`. The arrow points from sender to
receiver. IPv6 endpoints use brackets. TCP `seq`/`ack` are **absolute** numbers
(compare with `tcpdump -nn -S`); `win` is the raw, unscaled advertised window.
Flags: `S` SYN, `F` FIN, `R` RST, `P` PSH, `.` ACK, `U` URG, `E` ECE, `W` CWR.
TCP options include MSS, window scale, SACK and timestamps when present.
`length` is captured TCP/UDP payload bytes; `wire` is the original frame length,
including its link header. Fragments are labelled without invented transport
fields. ICMP shows type, code and common message names.

The compact DNS summary covers UDP port 53 (question/type, ID, response code and
answer count). TCP DNS, full resource records, HTTP and TLS details belong to
`analyze`/`chocolate`; the packet view does not run stream reassembly or print
HTTP bodies. JSON/CSV packet schemas and lossless Unix-nanosecond timestamps
are unchanged for scripts.

### Reading the flow table (1.2.2)

`crepe flows FILE [FILTER]` prints **one bidirectional flow per line**, with
aligned columns for UTC start date/time, duration (`HH:MM:SS.mmm`), protocol,
left/right endpoints, total packets and total wire bytes. This makes
`crepe flows traffic.pcap | head` show complete rows. Long IPv6 addresses and
large exact counters expand their columns instead of being truncated. Narrow
terminals may visually wrap long lines; use `less -S` to scroll horizontally.
Crepe does not insert newlines into a default flow row.

The `<->` arrow means both directions are counted together. Packet and byte
columns sum both directional counters without rounding or integer overflow.
The table resembles nfdump's layout but is not a claim of identical record
semantics: nfdump commonly emits separate directional flows. Crepe duration
covers the bidirectional record; byte counts include link headers. Full flow IDs,
per-direction counters, cumulative flags and end reasons are available through
`--details` or the unchanged JSON/CSV formats.

```sh
crepe flows traffic.pcap 'port 80'
crepe flows traffic.pcap --details
crepe flows traffic.pcap --format json
```

### Expanded flow details


`crepe flows FILE [FILTER] --details` prints expanded blocks instead of the
default one-record-per-line table. Lines wrap at 80 columns without truncating addresses or counters,
including when piped. For a known synthetic TCP conversation:

```text
2023-11-14 22:13:20.123Z TCP | duration 6.000s | CX-0000000000000001
192.0.2.10:50000 <-> 198.51.100.20:443
-> 3 packets, 162 bytes [FS.] | <- 2 packets, 108 bytes [FS.]
end: FIN both ways | observed TCP: closed
```

The timestamp is the earliest packet timestamp in UTC; duration is latest minus
earliest packet timestamp, displayed to milliseconds. It is not necessarily the full
connection lifetime. Endpoints retain canonical ordering: left is not necessarily
the client. `->` means left to right, `<-` means right to left. Flags are the
**union of observed TCP flags per direction**, not the last packet's flags.
Byte counters are exact original frame bytes including link headers, not payload
bytes; neither sizes nor counters are abbreviated or rounded. TCP state is a
passive observation, not proof of what happened at either endpoint.

`input ended` means the capture file ended, not that the connection closed.
`FIN both ways`, `TCP reset`, `idle timeout`, `active timeout` and
`capacity eviction` distinguish the other reasons. Interface/section/VLAN scope
is printed when non-default. IDs such as `CX-...` are local flow-record IDs;
use the persisted conversation `flow_id` returned by historical queries for
`crepe trace`.

With `--details`, one flow uses several lines, so `head` may cut a block in half.
The default table has one row per flow; JSON Lines and CSV are also unchanged.
`--details` only changes the human table format, not JSON/CSV output.
A filter such as `port 443` covers both directions. nfdump's extra event/NAT
columns have no direct equivalent in this packet-derived flow summary; absent
NAT/event fields are not evidence of packet loss.

### Historical and live analysis queries

`query STORE '...'` and a live recipe's `--query '...'` use **historical CQL**,
not BPF or nfdump's filter language. For example:

```sh
crepe query ./case 'dst.port == 443 | count'
crepe query ./case 'event.type == dns.query | select timestamp,dns.qname,src.ip'
crepe query ./case 'event.type == flow.end | group proto | sort bytes desc'
crepe chocolate -i lo0 --query 'event.type == flow.end | sum bytes as total' --query-interval 5
```

See [SCHEMA.md: Historical CQL](SCHEMA.md#historical-cql) and
[additional operators](SCHEMA.md#additional-historical-query-operators) for all
fields, comparisons, string operators, time expressions and pipeline stages.
See [the tool comparison](COMPARISON.md) for Zeek/SiLK and
[the packet/flow comparison](PACKET-FLOW-COMPARISON.md) for tcpdump/nfdump/nfpcapd.


## Using Crepe locally

The user-facing executable is **`crepe`**. Cargo is Rust's build manager and is
needed only for a source build or update. Ready-made binaries are available in
[Releases](https://github.com/cnc24/crepe/releases/tag/v1.2.2); Getting started
covers both binary and source installation.
Run the following examples from the cloned repository root, where `example.pcap`
and `fixtures/` are supplied synthetic test data:

```sh
crepe --help
crepe read example.pcap 'dst.port == 443'
crepe read example.pcap 'proto == tcp' --format json
crepe flows fixtures/flows.pcap
crepe analyze fixtures/protocols.pcap --format table
crepe profiles
crepe chocolate fixtures/protocols.pcap
crepe suzette fixtures/protocols.pcap

# Use a fresh store for this demo; identical imports are rejected.
DEMO_STORE=$(mktemp -d /tmp/crepe-demo.XXXXXX)
crepe suzette fixtures/dns.pcap --store "$DEMO_STORE"
crepe query "$DEMO_STORE" 'event.type == dns.response | select event.id,flow.id,payload'
crepe timeline "$DEMO_STORE" --limit 20
# Substitute an actual flow_id from the query output:
# crepe trace "$DEMO_STORE" FLOW_ID_FROM_QUERY

crepe interfaces
# macOS loopback (use lo on Linux); run traffic in another terminal to see packets:
crepe sucre -i lo0 --duration 5
# Receive a router/exporter's UDP records for 30 seconds:
crepe collect --listen 127.0.0.1:2055 --duration 30
```

Use `crepe COMMAND --help` for every option. `sucre` is the alias for live
`capture`; offline recipe selection uses `ingest --profile sucre`.
Empty output on a quiet interface is normal. Read/analysis need no capture
permissions; live capture does. Use your OS's libpcap permission setup.

Capture `--duration` is wall-clock bounded even on a quiet interface. SIGINT
flushes capture output; collector SIGINT commits the observations already
received. `--count` on collect counts UDP datagrams, including malformed ones.
The collector binds loopback by default; pass an explicit address for a router.
Export templates are scoped by source IP **and UDP port**, observation domain
and protocol version, and expire after 30 minutes without a template refresh.
Source-port changes require new templates. UDP loss and reorder are observable,
not repaired. Missing templates skip that set with a stable warning code.

NetFlow v5/v9 and IPFIX normalized fields: IPv4/IPv6 endpoints, ports,
protocol, counters, TCP flags, first/last time and sampling interval when
present in the record. Unknown/enterprise fields are retained as bytes.
Options records retain scope fields, including sampling configuration; they
are emitted separately and are not blindly applied to every flow. Counters
are the exporter's values, never automatically sampling-scaled. UDP template
withdrawal is rejected. No TCP/SCTP export transport or vendor-specific IE
interpretation is promised.

## Profiles

Validated TOML rejects unknown keys and versions. Sensor names are 1–64 ASCII
letters/digits/underscore/hyphen. `config [FILE]` prints effective JSON.

| Command | Purpose |
| --- | --- |
| `crepe sucre -i INTERFACE` | Live packet capture (alias for `capture`) |
| `crepe banane --listen udp://127.0.0.1:2055` | NetFlow v5/v9 and IPFIX collector (alias for `collect`) |
| `crepe chocolate -i INTERFACE` | Network analysis: packets, flows, reassembly, DNS/TLS/HTTP/SSH, anomalies and notices |
| `crepe suzette incident.pcapng --store ./case` | Capture forensics with persistent history for query/trace/timeline |
| `crepe maison FILE --config config/example.toml` | Use your own sensor, recipe and analysis resource settings |
| `crepe complete -i INTERFACE` | All implemented packet-derived analysis engines |

Chocolate, Suzette, Maison and Complete also accept a capture file directly.
When they open the interactive source menu, they first explain the selected
recipe in one sentence, followed by a short culinary aside. `--serious` or
`flair = false` keeps the explanation and removes the aside. Explicit file or
interface commands do not print this introduction; observation output remains
machine-readable.
Without a file or `-i`, these commands show a source-selection menu in an
interactive terminal. Scripts must specify the source explicitly. Maison accepts
`--config FILE` with the current flat TOML schema in `config/example.toml`;
the design's nested TOML example is not yet supported.

Live recipes process packets directly and emit JSON Lines during capture, without
writing a temporary PCAP. The default duration is 30 seconds (`--duration N`).
SIGINT ends capture, flushes pending flow/analysis observations and commits the
optional historical store. Flow summaries appear when flows expire/close or
capture stops. Live recipes publish a durable checkpoint at 1024 observations or after five
seconds, including on an idle interface. Clean stop commits the remainder; an
abrupt process kill can lose only the unpublished tail. Live output is in processing order and
is not capped at 10,000 observations.

Offline recipe output is sorted by timestamp and capped at 10,000 observations.
Use `--store PATH` to retain all observations for later queries. Without it,
the offline temporary store is removed after output. For formatted tables use
`read`, `flows` or `analyze`. `complete` runs the packet-derived engines;
add `--listen IP:PORT` to collect UDP exporter records into the same live store.

For scripted imports, `ingest --profile NAME` overrides the TOML profile;
Banane is a collector and is rejected for PCAP ingestion. `flows` remains the
flow-only command. An early private prototype profile mapping was incorrect: Chocolate
was flow-only and Banane was DNS-only. Main corrects those meanings to match
the design. Existing immutable stores remain readable; reprocess captures into
a new store if the corrected selection is required.

The optional DNS-change notice compares sorted RRsets (name/type/class),
ignores TTL changes, and tracks at most 4096 RRsets per import within `max_buffer_bytes` (an
independent notice-cache budget in addition to the TCP analysis budget).
New entries that exceed that budget are not retained. It is an
observation, not an attack verdict or blocking policy.

## Storage, restart and recovery

A store has `schema.json`, `data/<batch-hash>/*.parquet`, and during writing a
`writer.lock` and `.staging-<batch-hash>`. New files are partitioned below each
batch as `event=KIND/hour=UNIX_HOUR/*.parquet`; old flat batches remain readable. Rows flush at 1024 rows or 4 MiB;
a single row is limited to 1 MiB. New parts use ZSTD compression; existing
uncompressed parts remain readable. Files and the containing directory are
synced before an atomic directory rename publishes an import. Readers only
scan committed `data`; offline imports remain invisible until commit. Live
recipe/collector queries additionally merge the bounded live tail described
below. One writer is allowed per store.
Repeat imports of identical capture bytes for the same sensor are rejected.
Capture content is hashed before and after import; a changed file aborts the
batch. Prefer closed capture files for reproducible imports.
Use a new store to reprocess the same input with a different profile.

The current writer uses an OS advisory lock on a persistent `writer.lock` inode.
Its contents are `crepe-lock-v1 PID SESSION` while owned and empty after a clean stop;
the file's mere existence does not indicate a live writer. Never unlink this
modern lock file while writers might be running. On process death, the OS
releases ownership. The next writer acquires it and removes only abandoned
`.staging-<64-hex-hash>` directories before opening a new session. Published
batches remain immutable and are not deleted by recovery.

Legacy v1.0.0 locks contain only a PID and have no OS lock. They fail closed:
confirm the old writer is stopped, then remove that legacy lock manually once.
For a rollback to the historical binary, stop all writers and remove the empty
modern lock file first; the old binary otherwise cannot create its legacy lock.
Use local filesystems with working OS advisory locks, not an unverified network
filesystem, for multi-process writer exclusion.
Back up `schema.json` plus `data` together; no service process is needed to
read them after restart. Collector batches checkpoint periodically and commit the tail on normal
stop/SIGINT/SIGTERM. A forced kill can lose only the unpublished tail. Capture
raw exports separately if crash-loss-free collection is a requirement.

Unknown store schema versions fail closed. v0.3 had no historical store;
1.0 therefore introduces schema 1 without a legacy data migration. Future
incompatible schemas need an explicit migration tool, not silent coercion.
Queries have a 256 MiB DataFusion memory pool, 30-second execution deadline
and 10,000-row output cap; these are execution limits, not a promise that
whole-process RSS stays below 256 MiB. Parquet metadata and runtime overhead
also consume memory. Limit results explicitly when piping into other tools.

## Analysis limits

IP reassembly: up to 1024 datagrams, 8 MiB buffered bytes, 64 fragments per
datagram, 60 seconds capture-time lifetime, strict overlap rejection for both
IPv4 and IPv6. Interface/section/VLAN scope prevents cross-link collisions.
Incomplete/expired/evicted datagram counts are reported at completion.
TCP: 1024 directional streams and 4 MiB analysis buffer by default, bounded
out-of-order queue and overlap history. Conflicts, gaps, reset, timeout and
capacity loss produce anomalies. Captures starting midstream are marked;
bytes preceding the first observed sequence cannot be recovered. No endpoint
TCP stack is emulated and ACK numbers are not validated. Flow TCP state is
passively inferred from observed flags, not proof of a completed handshake.

DNS UDP/TCP decodes questions and common records. TLS emits the first cleartext
ClientHello/ServerHello per direction: SNI, ALPN, versions, ciphers, ECH presence.
It does not decrypt TLS, ECH, HTTP/2 or QUIC. HTTP/1.x emits the first request
and response headers per direction, not a body/archive or keep-alive request
log. SSH emits identification banners, not encrypted session contents.
Metadata headers are limited to 64 KiB, HTTP to 64 headers. Non-printable TLS
and SSH metadata is rejected; ALPN is represented as printable text.
Packet/flow counters cover captured wire packets; IP reassembly supplies
application decoding, not invented original packet sizes. `flows` skips IP
fragments and non-TCP/UDP with explicit counts.

## Release verification

```
python3 scripts/check-architecture.py
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --all-features --locked
cargo build --release --all-features --locked
python3 scripts/smoke-live.py
python3 scripts/smoke-dns.py
python3 scripts/smoke-platform.py
python3 scripts/benchmark.py --packets 200000
python3 scripts/package.py
```

Live tests use loopback and require capture permission. Linux CI runs only
these tests via sudo; ordinary builds/tests are unprivileged. Fuzz targets:
`cargo +nightly fuzz run parsers -- -max_total_time=60` from `fuzz/` with
cargo-fuzz installed. A deterministic 20,000-case mutation corpus also runs
in ordinary stable-Rust tests. Packaging fixes archive timestamps, owner and
file order; its checksum is reproducible for the same binary and documents.
This is not a claim of bit-identical Rust builds across toolchain versions.

## Errors and humor

Help, documentation and explanatory error details are English. Short French
introductions (`Sacré bleu!`, `Zut alors!`, `Oh là là!`) add the creperie's
personality without changing stable `CREPE-*` codes. Errors go to stderr;
JSON data on stdout stays machine-readable. Exit status is 0 for success,
2 for usage/CQL errors, and 1 for other runtime failures. Broken output pipes
exit successfully. To see an example: `crepe read example.pcap 'dst.port == baguette'`.
See [Schema and diagnostics](SCHEMA.md) for error-code families.

## Configuration precedence and presentation

For recipe/import/config commands, settings are applied in this order:
compiled defaults, `/etc/crepe/crepe.toml`, `$XDG_CONFIG_HOME/crepe/crepe.toml`
(or `~/.config/crepe/crepe.toml`), explicit `--config`, environment, then CLI
options. Layers use the current **flat TOML schema**, with strict unknown-key
validation. `CREPE_SENSOR`, `CREPE_PROFILE`, `CREPE_INTERFACE`, `CREPE_STORE`,
`CREPE_DNS_PORT`, `CREPE_FLAIR`, `CREPE_MAX_STREAMS` and
`CREPE_MAX_BUFFER_BYTES` are supported. `crepe config` prints effective settings.

Recipes can take default `interface` and `store` from configuration. Repeated
`--disable dns|tls|http|ssh|files|notices` suppresses selected observations;
`--enable NAME` removes configuration suppression. An explicit disable wins
if both CLI switches name the same module. This selects emitted observations;
shared packet/reassembly machinery remains active.

`crepe --serious ...` removes French runtime introductions. Configuration
`flair = false` does the same for commands loading configuration. Use
`--log-format json` for newline-delimited diagnostic objects on stderr
(`severity`, nullable `code`, `message`). Data on stdout is unchanged.

## Indicators, rules and file metadata

Set `intel_feed = "config/intel-example.jsonl"` and/or
`policy_rules = "config/policies-example.jsonl"` in TOML. Feeds are read once
at invocation start and never fetched from the network. Paths are relative to
the working directory. Indicators support exact ASCII domains (case/trailing-dot
normalized), IP addresses, CIDRs and SHA-256. Rules match an event type or `*`
and one exact `src.ip`, `dst.ip`, `proto`, `domain`, `sha256` or `anomaly.code`.
See the example JSON Lines files for their strict record format.

Limits: 8 MiB per file, 4096 bytes per line, 65,536 indicators, 512 CIDRs,
eight sources per exact indicator, 256 rules, at most 128 findings per observation.
`intel.match` and `notice.policy` carry `source_event_id`, preserving evidence
and conversation correlation. Findings are passive observations, not proof of
malicious activity. There are no active blocking actions or background feed updates.

`file.seen` describes the first supported HTTP body in each direction: byte
size, SHA-256 and optional declared MIME type. Body bytes are hashed incrementally
and not retained/extracted. POST/PUT bodies require a valid Content-Length.
Response hashing requires an observed opposite-direction request other than
HEAD/CONNECT. Missing, duplicate, invalid or oversized lengths never produce
a guessed hash; transfer encoding/chunked bodies are unsupported. Headers are
limited to 64 KiB and 64 fields, bodies to 64 MiB. Incomplete streams produce
anomalies rather than a complete-file hash. Keep-alive subsequent objects,
compressed-content decoding, encrypted bodies and disk extraction are not supported.

## Component plugins

Build with `--features plugins` (included in `--all-features`). Set
`plugins = ["plugins/example/manifest.json"]` in a recipe configuration.
The versioned interface is [plugins/api.wit](../plugins/api.wit). Each component
exports `process(event: string) -> string`: input contains `schema_version = 1`
and the historical `event` envelope; output is JSON Lines of objects. The host
wraps output as `notice.plugin`, with the plugin name and original event ID.

Manifests select event subscriptions, memory, per-event fuel and total event
budgets. Packet events never enter plugins, even for `*` subscriptions. There
is no WASI and no host import: filesystem, network, environment and process
access are unavailable. Nonempty permission requests and unknown API versions
are rejected. Guest state resides only in its bounded linear memory.

At most four components load per run. Each source component is at most 1 MiB;
linear memory is 64 KiB–16 MiB, per-event fuel 1–10 million, total calls at most
one million. Instantiation has a separate 50-million-fuel budget. Input/output
are capped at 64 KiB, output at 64 objects per call. Guest limits do not bound
JIT compilation/host runtime memory. A runtime trap, invalid output or exhausted
budget emits `anomaly.plugin` and disables that plugin while analysis continues.
There is no implicit permission escalation or recursive plugin event delivery.


## Service operation and metrics

Build with `--all-features` for capture and components. The supplied
`packaging/systemd/crepe.service` runs a configured sensor with structured logs,
loopback metrics and an explicit capture capability. Native DEB/RPM packages
install the unit and `/etc/crepe/crepe.toml`. Edit its interface first; `eth0` is
an example, not an automatic interface choice. Start it explicitly:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now crepe
sudo journalctl -u crepe -f
```

The service writes to `/var/lib/crepe`, closes each session after 24 hours and
is restarted by systemd. SIGINT and SIGTERM flush pending observations and
commit the tail. Previously checkpointed data remains readable after a crash;
modern locks recover on restart. Legacy PID-only locks still require the one-time
recovery procedure above. Investigate recurring crashes rather than relying on restarts.

On this Mac, run the same foreground sensor without systemd using a TOML file
with `interface = "lo0"` and an absolute writable `store` path:

```sh
crepe --serious --log-format json --metrics 127.0.0.1:9091 daemon --config sensor.toml --duration 60
curl http://127.0.0.1:9091/metrics
```

Only loopback metric listeners are accepted. `/metrics` exposes capture record,
byte, observation, exporter datagram and malformed-export counters, without
packet contents. Counters reset at process start; the endpoint is available
only while the command is running. Live row delivery is synchronous: slow
stdout/storage/plugins can cause libpcap drops, reported at session end.

## Building distributable packages

```sh
python3 scripts/licenses.py --check
python3 scripts/package.py
# On a native Debian/Ubuntu build host:
python3 scripts/package-linux.py --format deb
# On a native RPM distribution with rpmbuild installed:
python3 scripts/package-linux.py --format rpm
```

Packages include Crepe's applicable project license (see LICENSING.md), locked dependency notices/inventory and
Rust runtime notices. Linux packages must be built on their target distribution;
the RPM and DEB dependency metadata reflects native shared libraries. macOS
uses the tar archive. These scripts do not change repository visibility.

## Upgrades and public contracts

Back up the store's `schema.json` and `data/` together before replacing the
binary. Stop writers, install the new binary, and run a count/timeline query
before restarting capture. This revision continues to read schema 1 stores;
it adds event kinds without rewriting old rows. A future unsupported schema
fails with `CREPE-STORE-001`; never edit the manifest to bypass that check.
Plugins declare `api_version = 1` in their JSON manifest and receive the
versioned row envelope documented in `plugins/api.wit` and SCHEMA.md.
Consult DESIGN-STATUS.md for supported behavior and release limits.


## Compacting and retaining history

Stop the source writer, then build a new store:

```sh
crepe compact ./history --output ./history-compacted
# Retain observations at/after a Unix millisecond timestamp; keep untimed rows:
crepe compact ./history --output ./history-recent --since-ms 1791072000000
crepe query ./history-recent '* | count'
```

The output must not exist and must be outside the source store. Compaction
streams committed Parquet rows into bounded parts, preserves event/flow IDs,
and retains empty source-batch markers to prevent duplicate imports. It
reports read/retained/discarded counts. A source writer lock excludes concurrent
capture; readers can continue. Failures remove only the newly created output.
The original is never deleted or rewritten. Compare queries and back it up
before switching your sensor's store path. Automatic deletion and scheduled
retention are not enabled.


## Malformed traffic

Strict decoding remains the default. `crepe read FILE --tolerant` and
`crepe capture -i INTERFACE --tolerant` skip malformed packet payloads and
report the skipped count on stderr. Recipe commands accept `--tolerant`;
configuration accepts `tolerant_decode = true`. Recipes retain timestamped
`anomaly.decode` rows with the original stable parser code and record header,
then continue processing later packets. The supplied service configuration
enables this mode. Capture-container corruption, unsupported link types,
output/storage errors and plugin setup failures remain fatal; tolerant mode
must not hide lost framing or failed persistence.


## Combined packet and flow-export sensors

```sh
crepe complete -i lo0 --listen udp://127.0.0.1:2055 --store ./combined --duration 60
crepe query ./combined 'event.type == flow.export | group proto'
```

Use the appropriate Linux interface instead of `lo0`. Chocolate/Maison/Complete
accept `--listen`, and daemon configuration accepts `collector_listen =
"127.0.0.1:2055"`. One event pipeline and writer handles captured packets,
exporter flows/options/notices, security rules and components. Exported flow
rows retain exporter identity and counters; malformed datagrams become
`anomaly.export` and do not stop collection. A single ordered event-ID sequence
covers the session. Packet-derived and exported conversation identities remain
distinct to avoid falsely equating sampled/aggregated exporter records with
individual observed connections. UDP service work is capped at 64 datagrams
per packet/timer callback; sustained overload can cause socket drops.


## Live query windows

```sh
crepe chocolate -i lo0 --duration 30 --query 'event.type == packet | group proto | count' --query-interval 5
crepe complete -i lo0 --listen 127.0.0.1:2055 --store ./history --query 'event.type == flow.export | group src.ip | sum bytes as total'
```

`--query` evaluates the historical CQL grammar over consecutive processing-time
windows (default five seconds). Output is a `query.window` JSON envelope with
schema version, sequential index, observation count, elapsed milliseconds and
result `rows`. A quiet interface still flushes a nonempty window on its timer;
shutdown emits the remainder. Raw observation stdout is replaced by query
results; `--store` still retains all observations. A CQL `window 1m` stage
additionally buckets event timestamps **within each processing window**, not
across prior result envelopes. Late/exported data belongs to the processing
window in which it was received; no watermark/retraction semantics are implied.

Each processing window is capped at 10,000 observations and 16 MiB serialized
input. Overflow fails explicitly with `CREPE-CQL-LIMIT`; reduce the interval
for busy captures. Nothing is silently evicted. Query execution is synchronous
and bounded by the same memory/deadline constraints as historical queries;
expensive queries can delay capture and increase OS drops. This is a bounded
single-sensor query mode, not a distributed streaming SQL engine.


## Capture prefilters

For Ethernet `capture`/`sucre`, packet CQL automatically supplies a conservative
BPF hint when possible. Address/CIDR equality and protocol constraints reduce
work before userspace; the typed CQL evaluator remains authoritative. VLAN
traffic and IPv6 extension chains are deliberately admitted broadly. Unsupported
OR/negation/port-only expressions widen to no hint, never an unsafe exclusion.
Other link types keep the full userspace filter. Explicit `--bpf` takes precedence;
a failed automatic BPF compilation falls back to full capture with a diagnostic.
`--count` counts records delivered after the active BPF prefilter, before the userspace packet filter.


## Parallel live analysis

`crepe chocolate -i lo0 --workers 4` enables 1–16 live workers (`workers` in
TOML; default 1). The global TCP stream/buffer budgets and default flow/IP
fragment budgets are divided across workers, rather than multiplied. Each
worker has at most 16 queued owned capture records; the shared result queue
holds at most 128 observations. Full queues apply backpressure; OS capture
loss is reported through libpcap statistics. Configured stream and buffer
limits must be at least the number of workers.

Affinity uses canonical IP endpoints and link/VLAN context. Ports and terminal
protocol are intentionally excluded: later IPv6 fragments may hide extension
headers that reveal the transport protocol only in the first fragment. This
keeps first and subsequent fragments on the same worker. This coarser key can create hot spots between busy host pairs; each
worker still keeps full five-tuple flow/stream keys internally. Both directions
stay together. Output preserves per-worker processing order, not a global
capture-time sort. Event IDs remain unique within the live session. Offline
imports remain serial for repeatable observation identities even when the
configuration specifies multiple live workers.

The storage writer, rule/indicator evaluation and components consume worker
results centrally. Live query windows use processing arrival order; an observation
that finishes later can enter a later window. In-memory analysis budgets do not
include queue buffers, storage buffers, runtime code or plugin host overhead.
Partition fanout is capped at 16 specific event/hour keys plus a mixed fallback
per flush to avoid unbounded small-file creation from arbitrary timestamps.


## Querying the live tail with historical data

While a recipe or collector writes to `--store ./history`, another terminal can
run ordinary `crepe query ./history 'time >= now() - 30s | group event.type | count'`.
It merges committed Parquet with complete observations from the active live
journal, without waiting for a checkpoint. The journal contains only the same
metadata rows, not raw packet or HTTP body bytes. It is bounded to 4 MiB plus a
record/header and causes an earlier checkpoint if needed. Offline imports do
not expose a journal and retain all-or-nothing visibility.

Readers first open the current append-only journal inode, then freeze a list
of published batches. If its batch was published meanwhile, the Parquet copy
supersedes the entire journal; otherwise it is merged once. Journal rotation
replaces the inode rather than truncating a reader's file. Partial appended
lines are ignored. Session tokens associate it with the active OS writer lock,
so stale journals from crashed/previous writers are not exposed.

Hot rows are provisional until checkpointed: they can disappear after a writer
error/crash. Published rows remain durable. The legacy binary reads committed
Parquet only. Backups still use `schema.json` and `data/`; `.hot.jsonl` and
`.hot-new-*` are live staging internals, not an additional durable dataset.
