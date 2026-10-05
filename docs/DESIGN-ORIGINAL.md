> Historical planning document. Its proposed license choices are superseded by
> the repository LICENSE; this document grants no alternative license to Crepe.
> Profile naming has been updated to Chocolate at the owner's request.

# Crepe – Softwareplanung und technische Spezifikation

**Status:** Designentwurf v0.1  
**Plattform:** Linux  
**Sprache:** Rust  
**Binary:** `crepe`  
**Projektname/Branding:** Crêpe / Crepe

---

# 1. Produktidee

Crepe ist eine modulare Linux-Plattform zur Erfassung, Analyse und historischen Auswertung von Netzwerkverkehr.

Crepe soll die wichtigsten Anwendungsfälle von:

- tcpdump / libpcap
- NetFlow v5/v9
- IPFIX
- nfdump
- SiLK
- Zeek

unter einer gemeinsamen Architektur, CLI und Abfragesprache zusammenführen.

Crepe soll **nicht einfach vorhandene Programme aufrufen**, sondern die zentralen Funktionen selbst implementieren.

Das langfristige Ziel lautet:

> Crepe is a high-performance modular network observability, flow analytics and security telemetry engine for Linux.

Oder einfacher:

```text
tcpdump
   +
NetFlow/IPFIX
   +
nfdump
   +
SiLK
   +
Zeek-artige Analyse
       ↓
     CREPE
```

nfdump unterstützt heute bereits NetFlow, IPFIX und sFlow sowie Filtering, Aggregation, PCAP→Flow und Enrichment. SiLK konzentriert sich stark auf langfristige Flow-Speicherung und Analyse. Crepe übernimmt diese Konzepte, bekommt aber ein einheitliches Daten- und Query-Modell.

---

# 2. Designprinzipien

Crepe soll von Anfang an folgende Prinzipien verfolgen:

| Prinzip | Konsequenz |
|---|---|
| Linux-first | Keine Portabilitätskompromisse im Capture-Hotpath |
| Rust-first | Memory Safety ohne Garbage Collector |
| modular | Fast jede Funktion ist ein Modul |
| eine CLI | Keine Sammlung aus 30 Executables |
| eine Query-Sprache | Packet, Flow und L7 möglichst einheitlich |
| eventbasiert | Zeek-artige L7-Analyse |
| flow-aware | TCP/UDP-Verbindungen werden zusammengeführt |
| sichere Parser | Untrusted Traffic darf Crepe nicht crashen |
| zero-/low-copy | Keine unnötigen Payload-Kopien |
| bounded memory | Jeder zustandsbehaftete Teil besitzt Limits |
| scriptbar | JSON/NDJSON/CSV und stabile Exit-Codes |
| menschlich | CLI darf Spaß machen 😄 |
| machine-readable | Logs/API bleiben nüchtern und stabil |

---

# 3. Was Crepe ausdrücklich NICHT sofort sein soll

Version 1 soll kein vollständiger Ersatz sämtlicher Funktionen von Wireshark, Zeek, Suricata, tcpdump, nfdump und SiLK werden.

Insbesondere zunächst nicht:

```text
vollständige Wireshark-Protokollabdeckung
Zeek-Script-Kompatibilität
IDS-Signaturkompatibilität zu Suricata/Snort
aktive Firewall
automatisches Blocking
vollständige DPI für hunderte Protokolle
Web-GUI
verteilter Cluster
100-Gbit/s-Optimierung
AF_XDP
Machine Learning
```

Diese Architektur soll sie ermöglichen, aber nicht den MVP blockieren.

---

# 4. Die grundlegende Architektur

```text
                         CREPE
                           │
                   ┌───────┴───────┐
                   │     CLI       │
                   │    Config     │
                   │      DSL      │
                   └───────┬───────┘
                           │
                     Query / Policy
                           │
              ┌────────────┴────────────┐
              │                         │
        Streaming Engine         Historical Engine
              │                         │
              │                     DataFusion
              │                         │
              └────────────┬────────────┘
                           │
                      Crepe Events
                           │
        ┌──────────────────┼───────────────────┐
        │                  │                   │
        ▼                  ▼                   ▼
 Packet Engine         Flow Engine          L7 Engine
        │                  │                   │
 Ethernet            NetFlow v5             DNS
 VLAN                NetFlow v9             TLS
 IPv4/IPv6           IPFIX                  HTTP
 TCP/UDP/ICMP        Packet→Flow            SSH
        │                  │                   │
        └──────────────────┼───────────────────┘
                           │
                       Event Bus
                           │
       ┌───────────────────┼─────────────────────┐
       │                   │                     │
     Query              Storage              Security
                                             │
                                       Intel / Notice
                                       File / Anomaly
```

---

# 5. Wichtige Architekturentscheidung: kein zentraler Event-Bus im Hotpath

Logisch besitzt Crepe einen Event Bus.

Physisch soll aber **nicht jedes Paket durch eine einzige zentrale Queue laufen**.

Statt:

```text
Capture
   ↓
GLOBAL QUEUE
   ↓
alles
```

verwenden wir:

```text
NIC
 ↓
Capture
 ↓
Flow Hash
 ↓

Worker 0 ───── local state
Worker 1 ───── local state
Worker 2 ───── local state
Worker 3 ───── local state

   ↓
Events
   ↓
Storage / Output
```

Dadurch bleiben:

- TCP-State
- Flow-State
- Reassembly
- L7-Parser

für eine Connection möglichst auf demselben Worker.

Das ist für Performance und Lock-Vermeidung enorm wichtig.

---

# 6. Connection Affinity

Jede Connection bekommt einen kanonischen Flow-Key.

```rust
FlowKey {
    endpoint_a,
    endpoint_b,
    protocol,
    vlan,
}
```

Endpoints enthalten:

```text
IP
Port
```

Der Key wird richtungsunabhängig normalisiert.

Beispiel:

```text
10.0.0.5:54123 -> 8.8.8.8:443
```

und

```text
8.8.8.8:443 -> 10.0.0.5:54123
```

erzeugen denselben Flow-Key.

Danach:

```text
hash(flow_key) % worker_count
```

Damit landen beide Richtungen garantiert beim gleichen Worker.

---

# 7. Das interne Datenmodell

Wir trennen drei Dinge:

```text
PacketView
FlowRecord
CrepeEvent
```

## PacketView

Kurzlebige Ansicht auf ein Paket.

Sie soll möglichst Borrowing verwenden und nichts kopieren.

Enthält beispielsweise:

```text
timestamp
interface

ethernet
vlan

src_ip
dst_ip

src_port
dst_port

protocol

tcp_flags

payload slice
```

PacketViews werden standardmäßig **nicht dauerhaft gespeichert**.

---

# 8. FlowRecord

Ein Flow beschreibt Kommunikation über einen Zeitraum.

```rust
FlowRecord {
    flow_id,

    start_time,
    end_time,

    src,
    dst,

    protocol,

    packets_src,
    packets_dst,

    bytes_src,
    bytes_dst,

    tcp_flags_src,
    tcp_flags_dst,

    sensor,

    exporter,

    interfaces,

    sampling,

    metadata,
}
```

Dadurch können wir bidirektionale Flows darstellen.

---

# 9. Flow-ID

Jede erkannte Connection bekommt eine stabile ID innerhalb des Sensors.

Beispiel:

```text
CX-3f8219d420e2
```

Intern wahrscheinlich 128 Bit.

Alle späteren Ereignisse referenzieren diese ID.

```text
FLOW
 CX-3f8219d420e2

DNS
 CX-3f8219d420e2

TLS
 CX-3f8219d420e2

HTTP
 CX-3f8219d420e2

NOTICE
 CX-3f8219d420e2
```

Dadurch entsteht eines der wichtigsten Crepe-Features:

```bash
crepe trace CX-3f8219d420e2
```

Ausgabe:

```text
21:15:04.120  TCP connection established
21:15:04.141  TLS ClientHello
               SNI: example.org
               ALPN: h2

21:15:04.170  TLS ServerHello
21:15:05.212  28.3 KiB received
21:15:06.991  Connection closed
```

---

# 10. CrepeEvent

Zeek basiert stark auf Events, auf die Analyse- bzw. Scriptlogik reagiert. Dieses Prinzip übernehmen wir ausdrücklich.

Gemeinsamer Header:

```rust
EventHeader {
    id,
    event_type,

    timestamp,
    processing_timestamp,

    sensor_id,
    flow_id,

    src,
    dst,

    direction,

    schema_version,
}
```

Darunter typisierte Payloads.

```text
FlowStarted
FlowEnded

DnsQuery
DnsResponse

TlsClientHello
TlsServerHello

HttpRequest
HttpResponse

SshHandshake

FileSeen

IntelMatch

Anomaly

Notice
```

---

# 11. Module

Fast jede Funktion ist ein Modul.

Beispiele:

```text
crepe-capture
crepe-packet
crepe-flow

crepe-netflow5
crepe-netflow9
crepe-ipfix

crepe-dns
crepe-tls
crepe-http
crepe-ssh
crepe-dhcp

crepe-files
crepe-intel
crepe-anomaly
crepe-notice

crepe-storage
crepe-query
```

Ein Modul besitzt ein Manifest:

```text
name
version
api_version

dependencies

input_events
output_events

permissions
configuration
```

Beispiel:

```text
tls

requires:
    tcp-stream

consumes:
    stream.data

produces:
    tls.client_hello
    tls.server_hello
```

---

# 12. Profiles – die Crepe-Sorten 😄

Die lustigen Namen sind **Profiles**, keine unterschiedlichen Anwendungen.

## Crepe Sucre

Packet-Capture-Modus.

```text
capture
packet parser
filter
pcap
terminal output
```

Entspricht funktional grob:

```text
tcpdump
```

Aufruf:

```bash
crepe sucre -i eth0
```

---

## Crepe Banane

Flow Collector.

```text
NetFlow v5
NetFlow v9
IPFIX
Flow Storage
Flow Query
```

Aufruf:

```bash
crepe banane --listen udp://0.0.0.0:2055
```

---

## Crepe Chocolate

Deep Network Analysis.

```text
packet
flow
tcp-stream

DNS
TLS
HTTP
SSH
DHCP

anomaly
intel
notice
files
```

Das entspricht dem Bereich, in dem Zeek heute arbeitet.

```bash
crepe chocolate -i eth0
```

---

## Crepe Suzette

Forensik.

```text
PCAP
historical repository
timeline
correlation
trace
statistics
```

```bash
crepe suzette incident.pcapng
```

---

## Crepe Complète

Alles.

```bash
crepe complete
```

---

## Crepe Maison

Eigene Konfiguration.

```bash
crepe maison --config my-lab.toml
```

---

# 13. Profile sind kombinierbar

Canonical Syntax:

```bash
crepe run \
    --profile chocolate \
    --profile banane
```

Convenience:

```bash
crepe chocolate-banane
```

Zusätzlich:

```bash
--enable tls
--disable http
```

Beispiel:

```bash
crepe chocolate \
    -i eth0 \
    --disable http \
    --enable ja4
```

---

# 14. Capture Engine

## Stufe 1

libpcap.

Die aktuelle Rust-`pcap`-Bibliothek unterstützt Live-Capture, Interface-Erkennung, Packet Access und PCAP-Ausgabe.

Damit ist unser erster Capture-Backend:

```text
libpcap
```

## Später

```text
AF_PACKET / TPACKET_V3
```

## Noch später

```text
AF_XDP
```

AF_XDP wird ausdrücklich **nicht** in Milestone 1 gebaut.

Correctness zuerst.

---

# 15. PCAP / PCAPNG

Für Dateien verwenden wir zunächst `pcap-parser`.

Die Bibliothek unterstützt Streaming-Verarbeitung von PCAP und PCAPNG und berücksichtigt insbesondere PCAPNG-Besonderheiten wie mehrere Sections, Interfaces, unterschiedliche Zeitauflösungen und Endianness.

Version 1:

```text
READ:
✓ PCAP
✓ PCAPNG

WRITE:
✓ PCAP

PCAPNG-Writing später
```

Der Grund: das Serialisieren mit `pcap-parser` ist derzeit noch als experimentell dokumentiert.

---

# 16. Packet Parsing

Als erste Implementierung verwenden wir `etherparse`.

Es unterstützt derzeit unter anderem:

- Ethernet II
- VLAN
- ARP
- IPv4
- IPv6
- UDP
- TCP
- ICMP/ICMPv6

und besitzt einen Zero-Allocation-orientierten Parsing-Pfad.

MVP:

```text
Ethernet II
802.1Q VLAN

IPv4
IPv6

TCP
UDP
ICMP
ICMPv6
```

Später:

```text
MPLS
GRE
VXLAN
Geneve
PPPoE
```

---

# 17. IP Fragmentation

IPv4/IPv6-Fragment-Reassembly wird ein eigenes Modul.

```text
IP packets
    ↓
Fragment table
    ↓
complete datagram
```

Limits:

```text
max fragments/datagram
max fragment memory
max datagrams
fragment timeout
```

Überlappende oder kaputte Fragmente erzeugen:

```text
anomaly.ip_fragment_overlap
```

---

# 18. TCP State Engine

Für Chocolate benötigen wir vollständiges Connection Tracking.

```text
SYN
SYN/ACK
ACK
...
FIN/RST
```

State:

```text
NEW
SYN_SENT
ESTABLISHED
CLOSING
CLOSED
```

Crepe soll dabei auch unvollständige Captures tolerieren.

Also beispielsweise:

```text
MIDSTREAM
```

wenn Crepe erst mitten in einer Verbindung startet.

---

# 19. TCP Stream Reassembly

Für Zeek-artige L7-Analyse zwingend erforderlich.

```text
TCP segments
      ↓
sequence tracking
      ↓
out-of-order queue
      ↓
retransmission handling
      ↓
stream
```

Wichtig:

```text
max_stream_buffer
max_out_of_order
stream_timeout
```

werden konfigurierbar.

Ein kaputter TCP-Stream darf niemals unbegrenzt RAM fressen.

---

# 20. Protocol Detection

Portnummern dienen nur als Hint.

Nicht:

```text
80 = HTTP
443 = TLS
```

sondern:

```text
port
+
payload signatures
+
protocol state
=
Analyzer selection
```

Zeek besitzt ebenfalls ein Analyzer-Framework, über das Protokollanalysatoren dynamisch aktiviert/deaktiviert werden können.

Crepe verwendet beispielsweise:

```text
TCP stream
    ↓
Protocol Detector
    ↓
confidence scores
    ↓
TLS / HTTP / SSH / Unknown
```

---

# 21. Erste L7-Analyzer

Priorität:

| Prio | Protokoll |
|---|---|
| 1 | DNS |
| 1 | TLS |
| 1 | HTTP/1.1 |
| 1 | SSH |
| 2 | DHCP |
| 2 | NTP |
| 2 | SMTP |
| 3 | FTP |
| 3 | LDAP |
| 3 | Kerberos |
| 3 | SMB |
| später | HTTP/2 |
| später | QUIC |
| später | HTTP/3 |

Zeek besitzt heute bereits eine große Zahl solcher Protocol Analyzer; wir übernehmen das Architekturprinzip, nicht dessen Implementierung.

---

# 22. TLS

MVP analysiert:

```text
TLS ClientHello

version
supported versions
cipher suites

SNI
ALPN

extensions
supported groups

fingerprints
```

Später:

```text
JA3
JA4
certificate metadata
TLS key log support
TLS decryption
```

Wichtig:

Crepe darf nicht behaupten, bei verschlüsseltem Verkehr Dinge zu sehen, die nicht sichtbar sind.

Beispielsweise kann SNI durch ECH verborgen sein.

TLS 1.3 schützt außerdem wesentlich mehr Teile des Handshakes als ältere TLS-Versionen.

---

# 23. DNS

Unterstützung:

```text
UDP DNS
TCP DNS

query
response

A
AAAA
CNAME
MX
TXT
NS
PTR
```

Events:

```text
dns.query
dns.response
```

Beispiel:

```bash
crepe live -i eth0 \
 'type == dns.query && dns.qname ends_with ".example"'
```

---

# 24. HTTP

Zunächst HTTP/1.1.

Events:

```text
http.request
http.response
```

Felder beispielsweise:

```text
method
host
uri
status_code

user_agent
content_type
content_length
```

Body-Speicherung standardmäßig:

```text
OFF
```

Datenschutz und Speicherverbrauch sprechen klar dagegen.

---

# 25. NetFlow v5

Einfachster Flow-Collector.

Pipeline:

```text
UDP
 ↓
v5 header
 ↓
fixed records
 ↓
FlowRecord
```

MVP unterstützt:

```text
IPv4

src/dst
ports
protocol

packets
bytes

TCP flags

interfaces

AS

next-hop

timestamps
```

---

# 26. NetFlow v9

v9 benötigt einen Template Cache.

RFC 3954 definiert Template FlowSets und empfiehlt, Exportströme anhand von Exporter-IP plus Source-ID zu unterscheiden; Data FlowSets referenzieren vorher gelernte Template IDs.

Cache-Key:

```text
Exporter Address
+
Source ID
+
Template ID
```

State:

```text
templates
option templates
sequence
last seen
exporter uptime
```

Crepe erkennt:

```text
missing template
sequence gap
exporter restart
template replacement
invalid template
```

und erzeugt gegebenenfalls:

```text
anomaly.netflow.template_missing
anomaly.netflow.sequence_gap
```

---

# 27. IPFIX

IPFIX wird direkt nach NetFlow v9 umgesetzt.

Die Architektur wird gemeinsam:

```text
TemplateProtocol
    ├── NetFlow v9
    └── IPFIX
```

IPFIX verwendet ebenfalls Templates und Observation Domains; RFC 7011 definiert unter anderem Sequence Number und Observation Domain ID zur Trennung von Exportströmen.

MVP:

```text
UDP transport
```

Später:

```text
TCP
SCTP
```

---

# 28. sFlow

sFlow gehört auf die Roadmap, aber nicht in den ersten MVP.

```text
Milestone post-1.0
```

nfdump unterstützt sFlow ebenfalls, deshalb ist es sinnvoll, es langfristig abzudecken.

---

# 29. Packet → Flow

Crepe soll PCAP oder Live Traffic selbst in Flows umwandeln.

```text
Packet
 ↓
canonical FlowKey
 ↓
worker-local FlowTable
 ↓
FlowState
 ↓
FlowRecord
```

Timeouts:

```text
TCP inactive timeout
UDP inactive timeout

active timeout

FIN
RST
```

Werte sind konfigurierbar.

---

# 30. Crepe Query Language – CQL

Das wichtigste User-Feature.

Einheitliche Syntax:

```text
src.ip == 10.20.30.40
```

CIDR:

```text
src.ip in 10.0.0.0/8
```

Ports:

```text
dst.port in [80, 443, 8443]
```

Boolean:

```text
proto == tcp &&
dst.port == 443 &&
src.ip in 10.0.0.0/8
```

Strings:

```text
tls.server_name ends_with ".example.com"
```

Größen:

```text
flow.bytes > 100MB
```

Zeit:

```text
time >= now() - 30m
```

---

# 31. Pipeline-Syntax

```text
type == flow.end
| group src.ip
| sum flow.bytes as bytes
| sort bytes desc
| limit 20
```

Weitere Operatoren:

```text
select
group
count
sum
avg
min
max
distinct
sort
limit
top
timeline
```

Live zusätzlich:

```text
window
```

Beispiel:

```text
type == dns.query
| window 1m
| group src.ip
| count
| sort count desc
```

Live-State muss immer begrenzt sein.

---

# 32. DSL-Implementierung

Lexer:

```text
logos
```

Die aktuelle Logos-Version generiert einen deterministischen Lexer und optimiert ihn bereits zur Compile-Zeit.

Parser:

```text
eigener Pratt-/recursive-descent Parser
```

Warum kein kompletter Parsergenerator?

Weil unsere Grammatik klein ist und wir:

```text
gute Fehlermeldungen
typed AST
vollständige Kontrolle
```

wollen.

---

# 33. Typed AST

Aus:

```text
dst.port == 443 && flow.bytes > 10MB
```

wird:

```text
AND
├── Eq
│   ├── Field(dst.port : u16)
│   └── Literal(443 : u16)
│
└── GreaterThan
    ├── Field(flow.bytes : u64)
    └── Literal(10485760 : bytes)
```

Der Compiler erkennt dadurch früh:

```text
dst.port == "hallo"
```

als Typfehler.

---

# 34. Zwei Query-Ausführungswege

## Live

DSL:

```text
↓
AST
↓
Live Query Plan
↓
Predicate Bytecode
```

Sehr kleiner Interpreter bzw. später JIT-Optimierung.

---

## Historisch

DSL:

```text
↓
AST
↓
DataFusion LogicalPlan
↓
DataFusion
↓
Arrow/Parquet
```

Apache DataFusion ist dafür ausgesprochen passend: Es ist ein in Rust geschriebener, Arrow-basierter Query-Engine-Baukasten mit Filter-/Projection-Pushdown, Aggregationen, Sortierung, Parallelisierung und nativer Parquet-Unterstützung. Eigene Query-Sprachen können direkt Logical Plans erzeugen.

Dadurch bauen wir **keine Datenbank von Grund auf selbst**.

---

# 35. BPF Pushdown

Bei Live-Capture analysiert Crepe die Query.

Beispiel:

```text
proto == tcp &&
dst.port == 443 &&
tls.server_name == "example.org"
```

Kernel-kompatibler Teil:

```text
tcp dst port 443
```

wird als BPF-Filter an libpcap übergeben.

Danach gelangen nur relevante Pakete in Crepe.

Userspace prüft:

```text
tls.server_name
```

Damit:

```text
Crepe query
    ↓
Query planner
    │
    ├─ BPF predicate → Kernel
    │
    └─ advanced predicate → Crepe
```

---

# 36. Policy Language – CPL

Queries sagen:

> Was möchte ich sehen?

Policies sagen:

> Was soll Crepe tun, wenn etwas passiert?

Beispiel:

```text
on dns.query
where dns.qname == "bad.example"
{
    notice(
        severity: high,
        message: "Suspicious DNS domain"
    );
}
```

Oder:

```text
on flow.end
where flow.bytes > 1GB
{
    tag("large-transfer");
}
```

MVP-Actions:

```text
notice
tag
metric
log
```

**Keine aktive Netzwerkblockierung in v1.**

---

# 37. Zeek-artiges Intelligence Framework

Zeek besitzt ein Intelligence Framework zum Laden und Matchen von Indicators. Crepe bekommt dasselbe Konzept.

Indicators:

```text
IPv4
IPv6
CIDR

domain
hostname

URL

email

SHA256
SHA1

certificate fingerprint

JA3
JA4
```

Events aus:

```text
DNS
TLS
HTTP
Files
Flows
```

werden automatisch geprüft.

Treffer:

```text
intel.match
```

---

# 38. Notice Framework

Analyse und Alarmierung werden getrennt.

```text
Observation
    ↓
Detection
    ↓
Notice
    ↓
Output
```

Notice:

```text
id
timestamp

severity

type

flow_id

message

evidence

tags
```

Severity:

```text
info
low
medium
high
critical
```

---

# 39. Anomaly Engine

Zeeks `weird`-Konzept übernehmen wir als:

```text
anomaly
```

Beispiele:

```text
malformed_ipv4
tcp_overlap
invalid_tcp_sequence

dns_malformed

tls_invalid_record

netflow_template_missing
netflow_sequence_gap
```

Query:

```bash
crepe query \
 'type == anomaly | group anomaly.kind | count'
```

---

# 40. File Analysis

Zeek besitzt ein eigenes File Analysis Framework unabhängig vom Transportprotokoll. Crepe übernimmt dieses Prinzip.

Pipeline:

```text
HTTP ─┐
SMTP ─┼─→ FileStream → File Engine
FTP  ─┘
```

Metadata:

```text
size
mime

sha256

flow_id
protocol
filename
```

File Extraction:

```text
OFF by default
```

Aktivierbar:

```text
files.extract = true
```

---

# 41. Storage

Zwei getrennte Speicherformen.

## Raw Packets

```text
PCAP / PCAPNG
```

Keine eigene Erfindung.

## Events / Flows

```text
Apache Arrow
    ↓
Parquet
    ↓
ZSTD
```

Parquet ist columnar und unterstützt effizientes Lesen einzelner Spalten; Arrow konzentriert sich auf effiziente In-Memory-Berechnung.

---

# 42. Storage-Datasets

Nicht eine riesige Tabelle.

Sondern:

```text
flows/
dns/
tls/
http/
ssh/
files/
intel/
notices/
anomalies/
```

Alle teilen gemeinsame Felder:

```text
timestamp
sensor
flow_id
src
dst
```

---

# 43. Partitionierung

Beispiel:

```text
/var/lib/crepe/repository/

event=flow/
  date=2026-10-03/
    hour=21/
      sensor=edge01/
        part-00001.parquet

event=dns/
  date=2026-10-03/
    hour=21/
      sensor=edge01/
        part-00001.parquet
```

Nicht zu tief partitionieren, sonst entstehen Millionen kleiner Dateien.

Ein späterer:

```text
Compactor
```

führt kleine Segmente zusammen.

---

# 44. Hot Storage

Neueste Daten zunächst in RAM:

```text
Arrow RecordBatch
```

Dann:

```text
RAM
 ↓
segment writer
 ↓
Parquet
```

Query:

```text
--since 30s
```

kann RAM + Parquet kombinieren.

---

# 45. DataFusion

Historische Queries laufen über DataFusion.

Aktuell ist DataFusion 55.1.0 verfügbar und verwendet Arrow 59.2.x. Daher sollten wir Arrow/Parquet-Versionen nicht unabhängig auf „latest“ ziehen, sondern als kompatiblen Dependency-Satz pinnen.

Wichtig:

```text
DataFusion dependency family
=
gemeinsam versionieren
```

Nicht:

```text
DataFusion 55
+
Arrow 60
```

auf gut Glück kombinieren.

---

# 46. Output

Alle Commands unterstützen möglichst:

```text
table
json
ndjson
csv
parquet
```

Beispiel:

```bash
crepe query \
 'type == dns.query | limit 100' \
 --output json
```

---

# 47. CLI

Eine Binary:

```text
crepe
```

Canonical Commands:

```text
crepe live

crepe capture

crepe read

crepe collect

crepe query

crepe trace

crepe import
crepe export

crepe modules

crepe profiles

crepe status

crepe config

crepe daemon
```

---

# 48. Beispiele

Live:

```bash
crepe live -i eth0 \
 'proto == tcp && dst.port == 443'
```

Capture:

```bash
crepe capture \
 -i eth0 \
 -o capture.pcap
```

NetFlow:

```bash
crepe collect \
 --listen udp://0.0.0.0:2055
```

Historisch:

```bash
crepe query \
 --since 24h \
 'type == flow.end
  | group dst.ip
  | sum flow.bytes as bytes
  | sort bytes desc
  | limit 20'
```

Security:

```bash
crepe chocolate -i eth0 \
 'type == anomaly'
```

---

# 49. Konfiguration

Standard:

```text
/etc/crepe/crepe.toml
```

User:

```text
~/.config/crepe/crepe.toml
```

Priorität:

```text
defaults
    ↓
system config
    ↓
user config
    ↓
environment
    ↓
CLI
```

Der Rust-`config`-Crate unterstützt genau solche hierarchischen Konfigurationsquellen inklusive Dateien und Environment-Overrides.

---

# 50. Beispielkonfiguration

```toml
[crepe]
sensor = "edge01"

[capture]
interface = "eth0"
promiscuous = true

[storage]
path = "/var/lib/crepe/repository"
compression = "zstd"

[flows]
tcp_inactive_timeout = "60s"
udp_inactive_timeout = "30s"
active_timeout = "5m"

[modules]
dns = true
tls = true
http = true

[intel]
enabled = true

[ui]
flair = true
```

---

# 51. Lustige Fehlermeldungen 😄

Interne Fehler bleiben professionell.

Beispiel:

```text
code:
CREPE-NF9-0014

severity:
error

message:
Missing NetFlow v9 template 256
```

Human Renderer:

```text
Sacré bleu! NetFlow v9 template 256 is missing.
[CREPE-NF9-0014]
```

Severity-Flair:

```text
INFO
Voilà!

WARNING
Oh là là!

ERROR
Sacré bleu!

SEVERE
Mon dieu!

FATAL
Quelle catastrophe!
```

---

# 52. Wichtig: Logs bleiben ernst

Console:

```text
Sacré bleu! Repository is not writable.
```

JSON:

```json
{
  "severity": "error",
  "code": "CREPE-STO-0003",
  "message": "repository is not writable"
}
```

Syslog:

```text
CREPE-STO-0003 repository is not writable
```

Keine französischen Witze im SIEM. 😄

---

# 53. Serious Mode

Für Produktion:

```bash
crepe --serious
```

oder:

```toml
[ui]
flair = false
```

---

# 54. Fehlercodes

Namespace:

```text
CREPE-CAP-
CREPE-PCAP-
CREPE-PKT-
CREPE-FLOW-

CREPE-NF5-
CREPE-NF9-
CREPE-IPFIX-

CREPE-DNS-
CREPE-TLS-
CREPE-HTTP-

CREPE-QRY-
CREPE-STO-

CREPE-MOD-
CREPE-PLG-
```

Beispiel:

```text
CREPE-TLS-0007
```

---

# 55. Plugins

Drei Ebenen.

```text
Built-in
    → Rust

Trusted extension
    → Rust

Third-party
    → WebAssembly
```

Third-Party-Plugins laufen bevorzugt via Wasmtime.

Wasmtime ist ausdrücklich dafür gedacht, WebAssembly in Rust-Anwendungen einzubetten und bietet auch konkrete Plugin-Beispiele auf Basis des Component Models.

---

# 56. WASM Plugin API

Versionierte WIT-Schnittstelle.

Plugin darf beispielsweise:

```text
subscribe(event)

emit(event)

get_flow_metadata()

state_get()
state_set()

log()
```

Nicht automatisch:

```text
filesystem
network
process
environment
```

Permissions müssen im Manifest angefordert werden.

---

# 57. Plugin Limits

Jedes Plugin bekommt:

```text
memory limit
execution/fuel limit
event rate limit
state limit
```

Ein schlechtes Plugin darf Crepe nicht lahmlegen.

---

# 58. Nicht jedes Paket an WASM schicken

Ganz wichtig.

Built-in Hotpath:

```text
packet
TCP
reassembly
DNS/TLS/etc.
```

bleibt Rust.

WASM bekommt überwiegend:

```text
höherstufige Events
```

Sonst zerstören Plugin-Transitions unsere Performance.

---

# 59. Observability

Crepe überwacht sich selbst.

Metrics:

```text
crepe_packets_total
crepe_packets_dropped

crepe_flows_active
crepe_flows_total

crepe_events_total

crepe_netflow_packets
crepe_netflow_sequence_gaps

crepe_templates_active
crepe_templates_missing

crepe_stream_memory_bytes

crepe_storage_bytes

crepe_query_duration_seconds

crepe_plugin_errors
```

Prometheus Endpoint:

```text
127.0.0.1:9091/metrics
```

---

# 60. Logging

Rust:

```text
tracing
```

`tracing` unterstützt strukturierte Events und Spans und eignet sich besonders gut für nebenläufige Rust-Anwendungen.

Outputs:

```text
stderr
journald
JSON
```

---

# 61. Privilegien

Crepe soll nicht dauerhaft als root laufen.

Systemd beispielsweise:

```text
User=crepe

AmbientCapabilities=
  CAP_NET_RAW
  CAP_NET_ADMIN
```

Langfristig:

```text
capture helper
     ↓
shared ring
     ↓
unprivileged engine
```

Flow-Collector auf UDP 2055 braucht ohnehin keine Root-Rechte.

---

# 62. Sicherheitsregeln

Alle Netzwerkdaten sind untrusted.

Deshalb:

```text
keine unchecked lengths

keine unchecked indexing operations

keine panics durch Netzwerkinput

keine unbounded allocations

keine rekursiven Parser ohne Grenzen

keine dynamische Plugin-Berechtigung
```

---

# 63. Datenschutz

Crepe kann hochsensible Informationen sehen.

Default:

```text
payload storage       OFF
file extraction       OFF
HTTP body storage     OFF
raw packet retention  OFF
```

Metadata-first.

Retention muss konfigurierbar sein.

---

# 64. Testing

Vier Ebenen.

## Unit Tests

Für:

```text
parsers
flow state
DSL
templates
```

## Property Testing

`proptest`.

Die aktuelle Library bietet Property-Based Testing einschließlich Shrinking.

## Fuzzing

`cargo-fuzz`.

Targets mindestens:

```text
ethernet
ipv4
ipv6

tcp

netflow5
netflow9
ipfix

dns
tls
http

DSL
PCAPNG
```

## Integration Tests

Mit echten Capture Fixtures.

---

# 65. Regression-PCAPs

Repository:

```text
tests/fixtures/
```

Beispiele:

```text
simple_tcp.pcap

dns.pcap

tls13.pcap

ipv6.pcap

fragments.pcap

out_of_order_tcp.pcap

netflow5.bin
netflow9_templates.bin
ipfix.bin

malformed/
```

Jeder gefundene Parser-Bug bekommt danach ein Fixture.

Damit kommt derselbe Fehler nicht zweimal zurück.

---

# 66. Benchmarks

Criterion.

Criterion bietet statistische Benchmark-Vergleiche und eignet sich für Performance-Regressionen.

Benchmarks:

```text
packet parse

flow lookup

TCP reassembly

DNS parse

TLS ClientHello

NetFlow decode

query predicate

Arrow batch

Parquet writer
```

---

# 67. Performance-Regeln

Hotpath:

```text
no allocation per packet

no String creation per packet

no global mutex

batch processing

worker-local state

bounded channels

bounded buffers
```

Strings erst erzeugen, wenn wir sie wirklich brauchen.

Beispiel DNS:

Domainname kann zunächst intern als:

```text
bytes / compact representation
```

existieren.

---

# 68. Async

Tokio ja — aber nicht für jedes Paket.

Tokio für:

```text
control plane

UDP collectors

HTTP metrics

API

storage management
```

Dedicated Worker Threads für:

```text
packet parsing

flow tracking

TCP reassembly

L7 analysis
```

---

# 69. Skalierung

v1:

```text
ein Host
mehrere Worker
```

Später:

```text
                  Coordinator
                      │
        ┌─────────────┼──────────────┐
        │             │              │
      Sensor A      Sensor B       Sensor C
```

Ein Sensor analysiert lokal:

```text
capture
flows
streams
L7
```

und sendet überwiegend:

```text
events
```

statt rohe Pakete durchs Netzwerk zu bewegen.

Zeek verwendet ebenfalls Worker-basierte Clusterarchitekturen, um Traffic bei hohen Datenraten aufzuteilen und Session-Affinität zu erhalten.

---

# 70. Repository-Struktur

```text
crepe/
│
├── Cargo.toml
├── Cargo.lock
│
├── README.md
├── LICENSE
├── CHANGELOG.md
│
├── crates/
│   │
│   ├── crepe-core/
│   │
│   ├── crepe-event/
│   │
│   ├── crepe-dsl/
│   │
│   ├── crepe-query/
│   │
│   ├── crepe-cli/
│   │
│   ├── crepe-config/
│   │
│   ├── crepe-errors/
│   │
│   ├── crepe-capture/
│   │
│   ├── crepe-packet/
│   │
│   ├── crepe-flow/
│   │
│   ├── crepe-stream/
│   │
│   ├── crepe-netflow/
│   │
│   ├── crepe-ipfix/
│   │
│   ├── crepe-protocol-dns/
│   │
│   ├── crepe-protocol-tls/
│   │
│   ├── crepe-protocol-http/
│   │
│   ├── crepe-protocol-ssh/
│   │
│   ├── crepe-intel/
│   │
│   ├── crepe-notice/
│   │
│   ├── crepe-files/
│   │
│   ├── crepe-storage/
│   │
│   ├── crepe-plugin/
│   │
│   └── crepe-daemon/
│
├── fuzz/
│
├── benches/
│
├── tests/
│   └── fixtures/
│
├── docs/
│
├── packaging/
│   ├── systemd/
│   ├── deb/
│   └── rpm/
│
└── plugins/
```

---

# 71. Erste Dependencies

CLI:

```text
clap
```

Die aktuelle 4.6-Reihe ist gut dokumentiert und unterstützt subcommands und derive-basierte CLI-Strukturen.

Capture:

```text
pcap
pcap-parser
```

Packets:

```text
etherparse
```

Serialization:

```text
serde
serde_json
toml
```

Config:

```text
config
```

Query lexer:

```text
logos
```

Analytics:

```text
datafusion
arrow
parquet
```

Observability:

```text
tracing
```

Plugin:

```text
wasmtime
```

Testing:

```text
proptest
criterion
cargo-fuzz
```

---

# 72. Lizenzstrategie

Crepe selbst würde ich wahrscheinlich:

```text
MIT OR Apache-2.0
```

lizenzieren.

Aber:

**Wir implementieren Funktionen selbst und kopieren nicht einfach Code aus SiLK.**

SiLK ist GPL-v2-artig lizenziert.

nfdump steht dagegen unter einer BSD-Lizenz.

Trotzdem ist eine unabhängige Implementierung architektonisch sinnvoller.

---

# 73. Branding-Hinweis

Brand:

```text
Crêpe
```

Technische Namen:

```text
crepe
crepe-core
crepe-dns
```

Keine Umlaute oder Sonderzeichen in:

```text
Binary names
package names
crates
paths
environment variables
```

`Crêpe Chocolate` ist der aktualisierte Profilname für die tiefe Netzwerkanalyse.

---

# 74. Entwicklungsphasen

## Milestone 0 – Foundation

Ziel:

```text
Repository baut.
Tests laufen.
CI funktioniert.
```

Enthält:

```text
Cargo Workspace
core
errors
event
config
cli
```

---

# 75. Milestone 1 – Sucre

Ziel:

```bash
crepe read test.pcap \
 'src.ip == 10.0.0.5 && dst.port == 443'
```

muss funktionieren.

Enthält:

```text
PCAP reader
PCAPNG reader

Ethernet
VLAN

IPv4
IPv6

TCP
UDP
ICMP

DSL
AST

Filter engine

table output
JSON
```

**Das ist unser erstes wirklich benutzbares Crepe.**

---

# 76. Milestone 2 – Live Sucre

```bash
crepe sucre -i eth0 \
 'tcp && dst.port == 443'
```

Enthält:

```text
libpcap capture

interface discovery

BPF pushdown

packet statistics

PCAP output
```

---

# 77. Milestone 3 – Flow Engine

Enthält:

```text
canonical FlowKey

connection state

flow timeout

bidirectional counters

flow events

PCAP → flows
```

Danach:

```bash
crepe read traffic.pcap \
 --flows
```

---

# 78. Milestone 4 – Banane

Enthält:

```text
NetFlow v5

UDP collector

NetFlow v9

template cache

IPFIX

sampling

sequence handling

exporter state
```

Danach:

```bash
crepe banane \
 --listen udp://0.0.0.0:2055
```

---

# 79. Milestone 5 – Repository

Enthält:

```text
Arrow events

Parquet

partitioning

ZSTD

DataFusion

historical query
```

Danach:

```bash
crepe query \
 --since 24h \
 'type == flow.end | group src.ip | count'
```

---

# 80. Milestone 6 – Chocolate Core

Der große Zeek-Schritt.

Enthält:

```text
TCP state machine

TCP reassembly

protocol detection

DNS
TLS
HTTP
SSH
```

Danach:

```bash
crepe chocolate -i eth0
```

---

# 81. Milestone 7 – Security

```text
Anomaly Engine

Intel Engine

Notice Engine

Policies

File metadata

SHA256
```

---

# 82. Milestone 8 – Plugins

```text
WASM Component API

plugin manifests

permissions

limits

event subscriptions
```

---

# 83. Milestone 9 – Hardening

```text
fuzzing

malformed capture corpus

performance testing

memory-pressure tests

packet loss monitoring

crash recovery

repository recovery

long-running tests
```

---

# 84. Milestone 10 – Crepe 1.0

Voraussetzungen:

```text
stable CLI

stable Event Schema v1

stable DSL v1

stable Plugin API v1

documentation

systemd unit

DEB/RPM

benchmark suite

fuzz suite

upgrade path
```

---

# 85. Nach Version 1

Roadmap:

```text
sFlow

MPLS
VXLAN
GRE

SMTP
FTP
LDAP
Kerberos
SMB

HTTP/2

QUIC
HTTP/3

JA3 / JA4

YARA

GeoIP
ASN
Tor enrichment

SiLK import
nfdump import

IPFIX export

distributed sensors

central coordinator

remote query

AF_PACKET

AF_XDP

optional API/UI
```

---

# 86. Die ersten konkreten Issues

Damit würde ich nach dieser Planung tatsächlich anfangen:

```text
CREPE-001
Create Rust workspace

CREPE-002
Create crepe CLI binary

CREPE-003
Implement error model and French CLI renderer

CREPE-004
Define core network types

CREPE-005
Define EventHeader and EventType

CREPE-006
Implement CQL lexer

CREPE-007
Implement CQL parser

CREPE-008
Implement typed AST

CREPE-009
Implement PCAP reader

CREPE-010
Implement PCAPNG reader

CREPE-011
Implement Ethernet parsing

CREPE-012
Implement IPv4/IPv6 parsing

CREPE-013
Implement TCP/UDP parsing

CREPE-014
Implement Packet filter evaluator

CREPE-015
Implement table output

CREPE-016
Implement JSON output

CREPE-017
Add PCAP test fixtures

CREPE-018
Add fuzz targets

CREPE-019
Add benchmark harness

CREPE-020
Ship Crepe 0.1 Sucre
```

---

# 87. Der allererste funktionsfähige Build

Das erste echte Ziel ist bewusst winzig:

```bash
$ crepe read example.pcap \
    'dst.port == 443'
```

Ausgabe:

```text
TIME            SRC                  DST                 PROTO   LEN
21:31:02.111    192.168.1.20:51321   1.2.3.4:443         TCP     74
21:31:02.132    1.2.3.4:443           192.168.1.20:51321  TCP     74
```

Fehler:

```bash
$ crepe read nope.pcap
```

```text
Sacré bleu! Could not open 'nope.pcap'.
[CREPE-PCAP-0001]
```

Wenn **das** sauber funktioniert, entwickeln wir weiter.

Nicht vorher NetFlow.

Nicht vorher TLS.

Nicht vorher WASM.

Nicht vorher DataFusion.

---

# 88. Definition of Done für Crepe 0.1

Crepe 0.1 ist fertig, wenn:

```text
✓ cargo build --release

✓ cargo test

✓ PCAP lesen

✓ PCAPNG lesen

✓ Ethernet/VLAN

✓ IPv4/IPv6

✓ TCP/UDP/ICMP

✓ CQL Lexer

✓ CQL Parser

✓ typed AST

✓ Filter

✓ table output

✓ JSON output

✓ stabile Error Codes

✓ französische CLI-Errors 😄

✓ keine Panic bei bekannten malformed-PCAP-Fixtures

✓ Benchmark-Baseline vorhanden

✓ README erklärt Installation und fünf Beispielcommands
```

Dann taggen wir:

```text
v0.1.0
```

Erst danach kommt Live Capture.

---

# 89. Wichtigste Architekturregel des gesamten Projekts

Die Regel, an die wir uns während der Entwicklung halten sollten:

> **Correctness → Architecture → Observability → Performance → Features**

Nicht:

```text
OMG AF_XDP!!!
```

bevor überhaupt ein IPv6-Paket korrekt geparst wird. 😄

Und noch eine:

> Kein Feature darf verlangen, dass der Crepe-Core ein bestimmtes Protokoll kennt.

Der Core kennt:

```text
events
modules
flows
queries
```

Das DNS-Modul kennt DNS.

Das TLS-Modul kennt TLS.

Das NetFlow-Modul kennt NetFlow.

Genau dadurch kann Crepe langfristig wachsen, ohne irgendwann unwartbar zu werden.

---

# 90. Zielbild

Wenn Crepe irgendwann erwachsen ist, soll Folgendes möglich sein:

```bash
crepe complete -i eno1
```

und anschließend:

```bash
crepe query --since 24h \
 'src.ip == 10.20.30.40 | timeline'
```

mit einer Ausgabe wie:

```text
09:14:01  DNS   github.com → 140.82.x.x

09:14:01  FLOW  10.20.30.40:53122 → 140.82.x.x:443

09:14:01  TLS   github.com
                TLS 1.3 / h2

09:14:02  FLOW  148 KiB received

09:17:52  DNS   suspicious.example

09:17:52  INTEL Threat intelligence match
                source: foo-feed

09:17:52  NOTICE HIGH
                suspicious domain contacted
```

Alles aus:

```text
Packets
+
Flows
+
DNS
+
TLS
+
Threat Intel
```

mit **einer einzigen Syntax und einer einzigen Flow-ID**.

Das ist für mich die eigentliche Vision von Crepe.