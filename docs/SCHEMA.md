# Public contracts

CLI compatibility starts with 1.0: existing commands/flags and error-code
meanings are preserved within 1.x. New optional fields and event kinds may
be added. Consumers must ignore unknown fields/kinds and inspect
`schema_version`. Rust crates are workspace implementation APIs and are not
published to crates.io as a stable external SDK.

Packet JSON uses schema 2. Flow JSON uses schema 4 from 1.4.0, adding the `tcp_reuse` end reason.
Schema 3 introduced `first_sequence`: the original capture-record anchor of an observed flow instance. Application JSON
uses schema 2, adding `evidence` (packet references, completeness and scope), with `packet`, `dns`, `protocol`, `anomaly`, `midstream` and
`reassembled`. `event_type` is `dns.query`, `dns.response`, `protocol` or
`anomaly`; the tagged `protocol.type` distinguishes TLS, HTTP and SSH events.
Only the completion event for a fragmented datagram has `reassembled=true`.
Its packet header identifies the completing capture record. Reconstructed
application payload is not a captured-wire packet and is not used to inflate
wire counters.

Historical store schema 2 (new stores from 1.3.0) is Arrow/Parquet with these columns:

| Columns | Type / meaning |
| --- | --- |
| event_id, flow_id, sensor, source, event_type | Non-null UTF-8 |
| conversation_id, identity_status | UTF-8 in schema 2; nullable when reading legacy schema 1 |
| timestamp_ns | Nullable UTF-8 decimal Unix nanoseconds, lossless |
| timestamp_ms | Nullable signed 64-bit Unix milliseconds for queries |
| src_ip, dst_ip, proto | Nullable UTF-8 |
| src_port, dst_port, packets, bytes | Nullable unsigned 64-bit |
| payload | Non-null JSON text with full source observation |

`event_id` is BLAKE3 over length-prefixed sensor, source identity, ordinal.
Capture source is the content hash; exporter source is a unique collection
session identity. Stable same-input/sensor/profile imports reproduce event
IDs across processes/stores for the same implementation and serial input order.
In schema 2, `conversation_id` hashes sensor, source and the canonical
bidirectional endpoint/protocol/link key. `flow_id` hashes that tuple identity
plus the first capture record assigned by bounded flow accounting, with a
versioned domain separator. Closing packets retain the assigned instance.
Serial and affinity-worker pipelines use the same anchor and identity function.
This is an **observed flow instance**, not proof of endpoint TCP state. Flow
idle/active timeouts, capacity eviction and observed FIN/RST define boundaries;
unobserved closes and reused tuples without an observed boundary remain uncertain.

`identity_status` is `instance`, `unassigned` or `exported`. Missing timestamps,
fragment-only packet paths, packet-only profiles and expired ancestry mappings
can leave `flow_id` empty (`unassigned`); the engine does not guess a connection.
The packet-to-instance ancestry index retains at most 65,536 record mappings.
`conversation.id` and `identity.status` are query aliases for the new columns.
Exporter IDs retain exporter/domain provenance and are not declared identical to
packet-derived instances based only on a matching tuple.

Schema-1 stores remain readable with their ORIGINAL tuple-level `flow_id`
semantics and null new columns. Trace warns about this distinction. They are
read-only from 1.3.0: imports and compaction cannot silently upgrade them. Reimport
original captures into a NEW store for schema-2 identities. Without originals,
retain the old store and its known limitations; do not manufacture instance IDs.

Counts depend on event type. Packet rows have 1 and wire bytes; flow.end rows
have bidirectional captured counters; flow.export has exporter counters;
application/notice rows leave counters null. Filter `event.type` before
summing so packet and flow summaries are not double-counted.

## Historical CQL

```
dst.port == 443 && (proto == tcp || proto == udp) | select src.ip,dst.ip,bytes
sensor == lab | group event.type | sort count desc | limit 20
event.type == flow.end | group proto | sort bytes desc
flow.id == HASH | sort timestamp
* | count
```

Fields: `event.id`, `flow.id`, `event.type`, `sensor`, `source`, `timestamp`
(milliseconds), `timestamp_ns`, `src.ip`, `dst.ip`, `src.port`, `dst.port`,
`proto`, `packets`, `bytes`, `payload`; underscore aliases are accepted.
`flow.packets`/`flow.bytes` alias the counters. Filters support `==`, `!=`,
`<`, `<=`, `>`, `>=` (ordering only numeric fields), `&&`, `||`, `!` and
parentheses. String values may be bare tokens or double quoted, without
backslash escapes. Numeric fields accept integers and binary `KB`/`MB`/`GB` suffixes. Null follows SQL
three-valued logic. No arbitrary SQL, filesystem functions, joins or writes.

Stages: `select field,...`, `group field,...` (count and sums of packets/bytes),
`count`, `sort field [asc|desc]`, `limit 1..10000`. Stages execute in order;
referencing a field removed by a previous projection fails. At most eight
stages, 16 KiB query input, 1024 filter tokens and 32 nesting levels.
Packet CQL remains its typed packet predicate grammar with CIDR and port
lists. Historical CQL also supports CIDR membership and port lists.

## Stable diagnostic code families

`CREPE-EVIDENCE-001` covers invalid/unavailable evidence requests and bounded
investigation selections; `CREPE-CORRELATE-001` covers correlation input/budget
failures. Both use exit 1. Missing evidence without an export request is a JSON
availability result; hash mismatches and failed exports are errors.


`CREPE-CLI-001` invalid CLI; `CREPE-CQL-001` invalid query (exit 2).
`CREPE-CONFIG-001`, `CREPE-STORE-001`, `CREPE-ENGINE-001` configuration,
storage and orchestration failures (exit 1). Existing capture/packet/flow
codes are retained. Analysis codes: `CREPE-IP-001`, `CREPE-TCP-001/002`,
`CREPE-DNS-001`, `CREPE-TLS-001`, `CREPE-HTTP-001`, `CREPE-SSH-001`,
`CREPE-L7-001`, `CREPE-ANA-001/002`. Collector: `CREPE-COLLECT-001` runtime;
`CREPE-NETFLOW-001` malformed export; `CREPE-NETFLOW-TEMPLATE`,
`CREPE-NETFLOW-SEQUENCE`, `CREPE-NETFLOW-RESTART` observational notices.
`CREPE-NOTICE-DNS-CHANGE` reports an RRset change, not a security conclusion.
French CLI framing is intentionally humorous; machine consumers use codes.


### Additional historical query operators

Historical filters support `src.ip in 192.0.2.0/24`, `dst.port in [80, 443]`,
string `contains`, `starts_with`, `ends_with`, and `time >= now() - 30m`.
Time offsets accept ms/s/m/h/d; `time` aliases timestamp milliseconds.
Derived nullable fields: `tls.server_name`, `dns.qname` (first question),
`http.host`, `http.method`, `http.status`, `file.sha256`, `file.size`,
`anomaly.code`. Missing payload properties are null. Underscore aliases work.

Additional stages: `sum|avg|min|max FIELD as ALIAS`, `distinct FIELD`,
`top N FIELD`, `timeline`, and `window DURATION` (1s to 24h). Windows bucket
stored timestamps into `window_start_ms`; they are historical grouping windows,
not streaming watermark semantics. `group FIELD | count` counts original rows.
A bare group still emits count, packets and bytes sums for compatibility.

```sh
crepe query ./history 'tls.server_name ends_with ".example.test" | top 10 src.ip'
crepe query ./history 'event.type == flow.end && bytes >= 1KB | group src.ip | avg bytes as mean | sort mean desc'
crepe query ./history 'event.type == packet | window 1m | group proto | count'
```

### Security, file and plugin observations

`file.seen` payload protocol metadata contains `size`, lowercase `sha256` and
optional `mime`. Only complete supported Content-Length bodies are hashed;
no digest is emitted for an incomplete/ambiguous/unsupported transfer.
`intel.match` and `notice.policy` payloads contain `source_event_id` and a
structured `finding`. `notice.plugin` has `plugin`, `source_event_id`, `data`.
`anomaly.plugin` records `plugin`, `source_event_id`, `code`, `message`, and
`disabled: true`. Findings are observations, not blocking actions.

Plugin input is JSON `{ "schema_version": 1, "event": <historical row> }`.
Its event ID is identical to the corresponding emitted/stored row ID. Output
is JSON Lines of objects wrapped by the host as notices. Plugin API v1 has
one component export, `process(string) -> string`, and no host capabilities.
New diagnostic families: `CREPE-FILE-001`, `CREPE-INTEL-001`,
`CREPE-INTEL-MATCH`, `CREPE-NOTICE-POLICY`, `CREPE-PLG-001`, `CREPE-METRICS-001`.


### Live query result envelopes and provisional history

Live `--query` output is a `query.window` envelope with `schema_version = 1`,
`index`, `observations`, `elapsed_ms` and `rows`. It is query output, not an
additional persisted observation. `CREPE-CQL-LIMIT` identifies a processing
window exceeding its explicit row/byte budget. `anomaly.decode` retains the
parser code/header for skipped malformed packet payloads; `anomaly.export`
retains malformed UDP exporter diagnostics in combined sensors.

Ordinary history queries can include complete provisional rows from the active
bounded live journal. Their event IDs remain unchanged at checkpoint. A crash
or failed session can discard that tail; committed Parquet rows are durable.
Atomic offline imports remain invisible until commit. All published batches
and any provisional snapshot use the same Arrow schema 2 in new stores.

## Raw packet/link CLI output (1.2.3)

The 1.2.3 raw-output extension did not change historical storage. Raw `read`/`capture` JSON
also includes non-IP link records: capture header, linktype, optional source and
destination MAC, EtherType, VLAN IDs, protocol and textual details. Such records
have no `src`/`dst` IP endpoint. Existing IP packet JSON is unchanged. Packet CSV
appends `src_mac,dst_mac,ether_type,linktype` to its original 13 columns. Consumers
should inspect `proto` and the available endpoint fields rather than assuming
every capture frame is IP.

## Evidence and policy additions (1.4.0)

Historical Arrow schema remains 2. Analysis payload schema 2 adds
`evidence.records` entries `{sequence, section, interface}`, `complete`, and
`scope`. Scope includes observed directional stream context and retransmissions;
it is not a minimal byte map. At most 4096 references are stored per state,
charged to memory limits. Overflow/anomaly evidence does not claim completeness.
Flow payload schema 4 adds `end_reason = tcp_reuse` for an observed new SYN.
Old analysis schema-1 events remain readable with their single-packet anchor.

CPL effects are historical rows `notice.policy`, `policy.tag`, `policy.metric`
and `policy.log`. Payload contains `source_event_id` and `effect` with
`rule_id`, `rule_version`, `program_version` (BLAKE3 of the original CPL text),
`event_type`, and action `data`. `policy.summary` records suppressed-notice
counts. Intel/legacy-rule findings add `source_version` (content hash of their
input feed/rules). These additive payload fields require no Parquet migration.

Raw manifests live under `STORE/raw/manifest.json`, separately from telemetry.
Entries retain source identity, content hash, byte count, wall-clock creation and
expiry, plus the first original packet reference/count for live PCAP chunks.
Original imports remain unchanged PCAP/PCAPNG; the reader detects their magic.
A manifest is provenance metadata, not a cryptographic signature of the operator.
Evidence always hashes the referenced raw file before and after reading it.

Additional error families: `CREPE-CPL-001` for policy syntax/action limits,
`CREPE-RAW-001` for raw retention/manifest errors. Existing error families remain.
