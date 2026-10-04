# Public contracts

CLI compatibility starts with 1.0: existing commands/flags and error-code
meanings are preserved within 1.x. New optional fields and event kinds may
be added. Consumers must ignore unknown fields/kinds and inspect
`schema_version`. Rust crates are workspace implementation APIs and are not
published to crates.io as a stable external SDK.

Packet/flow JSON uses schema 2 inherited from the prototype. Application JSON
uses schema 1, with `packet`, `dns`, `protocol`, `anomaly`, `midstream` and
`reassembled`. `event_type` is `dns.query`, `dns.response`, `protocol` or
`anomaly`; the tagged `protocol.type` distinguishes TLS, HTTP and SSH events.
Only the completion event for a fragmented datagram has `reassembled=true`.
Its packet header identifies the completing capture record. Reconstructed
application payload is not a captured-wire packet and is not used to inflate
wire counters.

Historical store schema 1 is Arrow/Parquet with these columns:

| Columns | Type / meaning |
| --- | --- |
| event_id, flow_id, sensor, source, event_type | Non-null UTF-8 |
| timestamp_ns | Nullable UTF-8 decimal Unix nanoseconds, lossless |
| timestamp_ms | Nullable signed 64-bit Unix milliseconds for queries |
| src_ip, dst_ip, proto | Nullable UTF-8 |
| src_port, dst_port, packets, bytes | Nullable unsigned 64-bit |
| payload | Non-null JSON text with full source observation |

`event_id` is BLAKE3 over length-prefixed sensor, source identity, ordinal.
Capture source is the content hash; exporter source is a unique collection
session identity. Stable same-input/sensor/profile imports reproduce event
IDs across processes/stores. `flow_id` in historical rows is a **conversation
correlation ID** over canonical bidirectional endpoints/protocol/link scope,
sensor and capture source. A reused tuple within one capture remains one
trace; distinct `flow.end` rows retain stable sensor/source/instance hashes in payload and
have unique event IDs. It is not a global connection identifier across
unrelated capture files. Collector conversation IDs include exporter/domain;
packet-derived and exporter-derived flows are not automatically declared
identical merely because a 5-tuple matches.

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
and any provisional snapshot use the same Arrow schema 1.
