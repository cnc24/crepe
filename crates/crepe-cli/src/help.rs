use clap::Command;
use std::fmt::Write;
pub const LOGO: &str = include_str!("../../../assets/crepe-logo.txt");
/// Derive the alias table from Clap so help and executable command names agree.
pub fn root(command: &Command) -> String {
    let mut table = String::from("Commands:\n  COMMAND      ALIAS                 PURPOSE\n");
    for sub in command.get_subcommands().filter(|c| !c.is_hide_set()) {
        let aliases = sub
            .get_all_aliases()
            .filter(|name| *name != "choclate")
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            table,
            "  {:12} {:21} {}",
            sub.get_name(),
            if aliases.is_empty() { "-" } else { &aliases },
            sub.get_about().map(ToString::to_string).unwrap_or_default()
        );
    }
    format!("{{about-with-newline}}\n{{usage-heading}} {{usage}}\n\n{table}\nOptions:\n{{options}}\nExamples:\n  crepe read traffic.pcap 'ip.src == 192.0.2.10' -vvX\n  crepe flows traffic.pcap --store ./flows\n  crepe flows ./flows '* | sort bytes desc | limit 10'\n  crepe forensics incident.pcap\n\nUse crepe COMMAND --help for filters, queries and examples.\nAliases select the same workflow; --serious changes diagnostics only.\n")
}

/// Keep examples in short and long help, including when reached through an alias.
pub fn configure(mut command: Command) -> Command {
    let names: Vec<_> = command
        .get_subcommands()
        .map(|s| s.get_name().to_owned())
        .collect();
    for name in names {
        let extra = match name.as_str() {
            "plan" => "Examples:\n  crepe plan --profile chocolate --profile banane\n  crepe plan --profile sucre --enable tls\n  crepe plan --config sensor.toml --disable http --disable files\n\nResolves built-in manifests, dependencies, budgets and lifecycle before any capture.\nA disabled required dependency is an error. Repeat --profile to combine recipes.",
            "raw-prune" => "Examples:\n  crepe raw-prune ./case --max-age-seconds 86400 --max-bytes 268435456\n\nTakes the store writer lock and removes expired/oldest manifest-owned raw copies.\nNever deletes original input files or historical rows. Stop writers first.\nRaw retention is opt-in with --keep-raw or [raw] enabled = true in configuration.",
            "correlate" => r#"Examples:
  crepe forensics incident.pcap --store ./case
  crepe correlate ./case --window 300
  crepe correlate ./case --since-ms 1700000000000 --until-ms 1700000300000

Schema-2 stores only. Reads fewer than 10,000 DNS/TLS/Intel observations (16 MiB
maximum); narrow the time interval if needed. Time bounds apply to BOTH DNS and
TLS observations, so include preceding DNS answers. Results are JSON Lines.
Direct or CNAME-linked A/AAAA answers must match visible SNI, TLS destination, client, sensor,
source and link context, within DNS TTL and --window seconds. Repeated candidates
are marked ambiguous; missing evidence produces unmatched results. These are
inferred relationships, not proof of causality. --cross-source allows same-sensor
capture sources; clock alignment remains unverified. Hidden names are not guessed.
Use timeline STORE --related EVENT_ID to view the linked observations together."#,
            "evidence" => r#"Examples:
  crepe query ./case 'event.type == intel.match | select event.id'
  crepe evidence ./case EVENT_ID
  crepe evidence ./case EVENT_ID --capture incident.pcap
  crepe evidence ./case EVENT_ID --capture incident.pcap --write evidence.pcap

EVENT_ID is the 64-character event_id, not flow_id. Follows notice/Intel parent
references to recorded reassembly inputs, or a legacy/flow anchor. Without
--capture, retained raw files are located automatically. provenance_complete
reports whether all observed analysis inputs are referenced (up to 4096).
This does not prove that unobserved network traffic never existed.
The original capture's content hash must match the stored source. Missing files
are reported explicitly; unrelated files are refused. --write never overwrites.
Live sources without a matching retained capture and legacy flow records may
have no retrievable original packet. Metadata is not a substitute for raw bytes."#,
            "logo" => "Examples:\n  crepe logo\n  crepe logo > crepe-logo.txt\n\nPrints the mascot and wordmark using only ASCII, without colors or terminal escapes.\nThe interactive root help also shows the logo; --serious hides that automatic banner.",
            "profiles" => {
                r#"Choose a workflow (listing profiles does not start capture):
  COMMAND      PROFILE / ALIAS   WHEN TO USE IT
  capture      sucre             Live packet summaries; use read for a capture file.
  inspect      chocolate         Packets, flows and DNS/TLS/HTTP/SSH analysis.
  forensics    suzette           Retain a case for later queries, timeline and trace.
  run          maison            Use the profile/settings from your configuration.
  full         complete          All implemented packet-analysis engines.
  collect      banane            Receive NetFlow v5/v9/IPFIX UDP exports.

Examples:
  crepe profiles
  crepe chocolate traffic.pcap
  crepe inspect traffic.pcap --store ./history
  crepe forensics traffic.pcap --store ./case
  crepe run traffic.pcap --config crepe.toml
  crepe capture -i lo0 --duration 10
  crepe collect --listen 127.0.0.1:2055 --store ./exports

inspect/chocolate and full/complete currently use the same analysis engines.
forensics/suzette retains ./crepe-cases/case-*/history by default; other file
recipes need --store to keep their observations. The source capture is copied only with --keep-raw or raw.enabled.
Recipe file input is fully processed before JSON Lines are printed (up to 10,000
observations); retained stores keep all observations for later queries.
Without a source, recipe commands offer a terminal source menu unless configuration
already selects an interface. Use crepe interfaces to choose your OS's interface.
crepe profiles prints a JSON catalog. It takes no profile-name argument.
Use crepe chocolate -h (or another command/alias) for that workflow's options.
Profile names in TOML and ingest --profile remain the recipe names above."#
            }
            "read" => {
                r#"Examples:
  crepe read traffic.pcap
  crepe read traffic.pcap 'dst port 443'
  crepe read traffic.pcap 'ip.src == 192.0.2.10' --format json
  crepe read http.pcap http -vvX
  crepe read traffic.pcap arp
  crepe read traffic.pcap -A | grep 'Host:'

Filter syntax: tcpdump/BPF or Crepe CQL with selected Wireshark field aliases.
CQL supports src.ip/dst.ip, src.port/dst.port, proto, ==, !=, &&, ||, !,
parentheses, IP in CIDR and port in [80,443]. Aliases include ip.src/dst/addr,
ipv6.src/dst/addr, tcp.srcport/dstport/port and udp.srcport/dstport/port.
http/dns/tls/ssh are packet-local tests; this is not full Wireshark syntax.
Quote the whole filter. BPF requires a live-enabled build (official releases).
-A and -X dump bytes after the link header; -XX includes the link header.
-v adds IP details; -vv adds available HTTP headers. These options require table
output. Use analyze for reassembly. Reading a file needs no capture permissions."#
            }
            "query" => {
                r#"Create a store first:
  crepe flows traffic.pcap --store ./flows
  crepe forensics traffic.pcap --store ./case

Examples (JSON Lines output):
  crepe query ./flows '* | sort packets desc | limit 10'
  crepe query ./flows 'bytes > 1000 | sort bytes desc'
  crepe query ./flows '* | group src.ip,dst.ip | sort count desc'
  crepe query ./case 'event.type == dns.query'
  crepe query ./case 'event.type == flow.end | select flow.id,src.ip,dst.ip,bytes'

Historical CQL uses predicates followed by | select, group, count, sort or limit.
This is not tcpdump/BPF or SQL. Quote the entire query. Results are bounded to
10,000 rows. In mixed stores, filter event.type before counting/grouping to avoid
mixing packet, flow and application observations. Flow src/dst are canonical
endpoints, not necessarily the initiator/responder. Use trace for a conversation."#
            }
            "ingest" => {
                r#"Examples:
  crepe ingest traffic.pcap --store ./history
  crepe ingest traffic.pcap --store ./history --profile chocolate --sensor lab
  crepe query ./history 'event.type == dns.query'

Imports observations into an atomic Parquet batch; stdout is a JSON import
summary, not packet output. A successful import is available to query/timeline/trace.
An identical batch cannot be imported twice. Use read for immediate packet output
or flows --store for flow-only history. The source capture is copied only with --keep-raw or raw.enabled."#
            }
            "trace" => {
                r#"Examples:
  crepe query ./case 'event.type == flow.end | select flow.id,src.ip,dst.ip'
  crepe trace ./case FLOW_ID

Replace FLOW_ID with a 64-character hexadecimal flow_id from query output,
not the short CX- identifier in the packet-derived flow table. Schema-2 flow_id
identifies an observed instance; conversation.id groups the endpoint tuple. Trace prints
chronological stored observations for that conversation as JSON Lines.
A flow-only store has no application observations; create a fuller case with
crepe forensics traffic.pcap --store ./case."#
            }
            "timeline" => {
                r#"Examples:
  crepe timeline ./case --limit 20
  crepe query ./case 'event.type == dns.query | sort timestamp asc | limit 20'

Reads an existing store and prints observations in chronological order as JSON
Lines. Create a case with crepe forensics traffic.pcap --store ./case first.
Use --related EVENT_ID for a common DNS/TLS/Intel/policy timeline with explicit
truncation; otherwise use query for filtering and trace for one flow instance."#
            }
            "compact" => {
                r#"Examples:
  crepe compact ./history --output ./history-compact
  crepe compact ./history --output ./recent --since-ms 1700000000000

Stop writers before compacting. The destination must be NEW; the source is kept.
--since-ms uses Unix milliseconds, not seconds. Untimed observations are retained.
Verify the new store with query before switching a service to it."#
            }
            "analyze" => {
                r#"Examples:
  crepe analyze traffic.pcap
  crepe analyze fixtures/dns.pcap --format table
  crepe analyze traffic.pcap --dns-port 5353

Emits DNS, TLS hello, HTTP/1.1 and SSH metadata after bounded reassembly; it does
not decrypt TLS. This command does not create a historical store. Use inspect
--store for packets/flows plus application observations, or forensics to retain
a case automatically. Use read for packet summaries and byte dumps."#
            }
            "inspect" | "full" | "run" => {
                r#"Examples:
  crepe inspect traffic.pcap --store ./history
  crepe full traffic.pcap --disable http --disable files
  crepe run traffic.pcap --config crepe.toml
  crepe query ./history 'event.type == dns.query'

File input is fully processed before JSON Lines are printed (up to 10,000
observations). Use --store to retain all observations for later queries; otherwise
file history is temporary unless configured. Live input streams observations.
Omit the source for a terminal menu unless configuration selects an interface.
inspect/chocolate and full/complete currently share the same analysis engines.
run/maison uses the configured profile (default: complete). Repeat --profile to
combine recipes. Use plan to inspect dependencies. --disable http also requires
--disable files, because file hashing depends on HTTP. --keep-raw requires --store. TLS is not decrypted.
Use profiles -h for workflow differences and forensics for an automatic case."#
            }
            "forensics" => {
                r#"Examples:
  crepe forensics traffic.pcap --store ./case
  crepe timeline ./case --limit 20
  crepe query ./case 'event.type == flow.end | select flow.id,src.ip,dst.ip'
  crepe trace ./case FLOW_ID

Alias: suzette. Retains a case by default in ./crepe-cases/case-*/history.
--store chooses its location. The source capture is copied only with --keep-raw or raw.enabled.
File input is fully processed before JSON Lines output (up to 10,000 observations);
query the retained store for more results. Use profiles -h to compare workflows."#
            }
            "capture" => {
                r#"Examples:
  crepe interfaces
  crepe capture -i lo0 'tcp port 443' --duration 10
  crepe capture -i any --duration 10 --write traffic.pcap
  crepe read traffic.pcap -vvX

lo0 is typical macOS loopback; Linux uses lo and also supports any.
Requires OS capture permissions. A quiet interface can produce no packets.
--count counts delivered records before filtering; --limit counts matches.
--write saves matching frames to a new file. --bpf is an additional BPF prefilter.
Use read -h for packet filters and dump options. Alias: sucre."#
            }
            "interfaces" => {
                r#"Examples:
  crepe interfaces
  crepe capture -i lo0 --duration 10

Lists libpcap interface names and available descriptions without starting capture.
Choose a listed name for capture -i or a recipe --interface. macOS commonly uses
lo0/en0; Linux uses lo and may provide any. Alias: interface."#
            }
            "collect" => {
                r#"Examples:
  crepe collect --listen 127.0.0.1:2055 --duration 30 --store ./exports
  crepe query ./exports 'event.type == flow.export | group proto'

Configure your exporter to send NetFlow v5/v9 or IPFIX UDP datagrams to this
address/port. This receives exports; it does not sniff packets or read nfdump files.
Default binding is loopback. Select a reachable local IP for remote exporters.
--count counts datagrams, including templates and malformed datagrams, not flows.
Without --store, observations are printed but not retained. Alias: banane."#
            }
            "config" => {
                r#"Examples:
  crepe config
  crepe config crepe.toml
  crepe run traffic.pcap --config crepe.toml

Validates configuration and prints effective settings as JSON; it does not write
a config file or start capture. Settings combine defaults, configuration files
and CREPE_* environment overrides. Use --config on the workflow you want to run."#
            }
            "daemon" => {
                r#"Examples:
  crepe config /etc/crepe/crepe.toml
  crepe daemon --config /etc/crepe/crepe.toml --duration 3600

Runs a configured live sensor and needs capture permissions. Configure interface,
store and resource limits first. --duration is seconds; the default is 24 hours.
Use your service manager to restart sessions. See docs/OPERATIONS.md for deployment."#
            }
            "update" => {
                r#"Examples:
  crepe update --check
  crepe update
  crepe update --output ./crepe-new

Checks the latest stable release from github.com/cnc24/crepe using curl and HTTPS.
Only a newer version is installed. Verifies SHA-256, stages the binary, then
atomically replaces it. --output must not exist. Package-manager/Cargo installs
must use their installer, or select a new standalone --output path.
Versions before 1.2.3 need a one-time manual upgrade to obtain this command."#
            }
            "licenses" => {
                r#"Examples:
  crepe licenses
  crepe licenses > crepe-licenses.txt

Prints the embedded project license and dependency notices. These remain available
after binary-only self-updates. See LICENSE and docs/LICENSING.md for usage terms."#
            }
            _ => continue,
        };
        command = command.mut_subcommand(name, |sub| sub.after_help(extra));
    }
    command
}
