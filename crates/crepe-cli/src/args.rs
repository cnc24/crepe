use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
#[derive(Parser)]
#[command(name = "crepe", version, about = "Packet capture and flow explorer")]
pub(crate) struct Cli {
    /// Disable French flair in runtime messages.
    #[arg(long, global = true)]
    pub serious: bool,
    /// Serve Prometheus counters on a loopback address (for example 127.0.0.1:9091).
    #[arg(long, global = true)]
    pub metrics: Option<std::net::SocketAddr>,
    /// Structured diagnostic output on stderr, independently of data on stdout.
    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Text)]
    pub log_format: LogFormat,
    #[command(subcommand)]
    pub command: Command,
}
#[derive(Clone, Copy, clap::ValueEnum)]
pub(crate) enum FilterSyntax {
    Auto,
    Cql,
    Bpf,
}

#[derive(Args)]
pub(crate) struct PacketArgs {
    /// Filter: CQL, tcpdump/BPF, or http/dns/tls/ssh/arp/lldp/eapol. BPF requires live support.
    pub filter: Option<String>,
    /// Select a grammar explicitly, or detect CQL fields automatically.
    #[arg(long, value_enum, default_value_t = FilterSyntax::Auto)]
    pub filter_syntax: FilterSyntax,
    /// Skip malformed packet payloads; capture-container and I/O errors still stop.
    #[arg(long)]
    pub tolerant: bool,
    /// Output encoding: readable table, JSON Lines, or CSV.
    #[arg(long, value_enum, default_value_t = Format::Table)]
    pub format: Format,
    /// Print packet bytes after the link header as safe ASCII (table output only).
    #[arg(short = 'A', long, conflicts_with = "hex")]
    pub ascii: bool,
    /// Hex and ASCII after the link header; repeat (-XX) to include it (table only).
    #[arg(short = 'X', long, action = clap::ArgAction::Count)]
    pub hex: u8,
    /// More packet metadata (-v); application headers (-vv). Combines with -X/-XX.
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// Stop after this many matching packets or link frames.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub limit: Option<u64>,
    /// Write matching packet bytes to a new PCAP (never overwrites).
    #[arg(short, long)]
    pub write: Option<PathBuf>,
}
#[derive(Args)]
pub(crate) struct FlowArgs {
    /// Capture file OR a previously created historical store directory.
    pub file: PathBuf,
    /// Packet filter before aggregation; a pipeline or bytes/packets predicate is a flow query.
    pub filter: Option<String>,
    #[arg(long, value_enum, default_value_t = FilterSyntax::Auto)]
    pub filter_syntax: FilterSyntax,
    /// Output encoding: readable table, JSON Lines, or CSV.
    #[arg(long, value_enum, default_value_t = Format::Table)]
    pub format: Format,
    /// Maximum tracked flows; at capacity, emit the flow with the earliest deadline.
    #[arg(long, default_value_t = 65536, value_parser = clap::value_parser!(u32).range(1..=1_000_000))]
    pub max_flows: u32,
    /// Show expanded directional counters, flags and end reasons instead of one row per flow.
    #[arg(long)]
    pub details: bool,
    /// TCP inactivity timeout in capture-timestamp seconds.
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..))]
    pub tcp_idle: u64,
    /// UDP inactivity timeout in capture-timestamp seconds.
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
    pub udp_idle: u64,
    /// Maximum flow lifetime in capture-timestamp seconds before emitting a record.
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..))]
    pub active_timeout: u64,
    /// Persist all generated flow records into this historical store.
    #[arg(long)]
    pub store: Option<PathBuf>,
    /// Historical CQL on aggregated flows, identical to crepe query STORE QUERY.
    #[arg(long)]
    pub query: Option<String>,
    /// Sort descending by a counter; flows/count requires --group or a grouped query.
    #[arg(short = 'O', long, value_parser = ["packets", "bytes", "flows", "count", "timestamp"])]
    pub sort: Option<String>,
    /// Group/correlate flow endpoints, e.g. src.ip,dst.ip (also totals packets/bytes).
    #[arg(long)]
    pub group: Option<String>,
    /// Count selected flows, per group when --group is supplied.
    #[arg(long)]
    pub count: bool,
    /// Maximum query result rows, after sorting/aggregation.
    #[arg(short = 'n', long, value_parser = clap::value_parser!(u32).range(1..=10000))]
    pub limit: Option<u32>,
}
#[derive(Subcommand)]
pub(crate) enum Command {
    /// Print the Crepe mascot and wordmark as plain ASCII.
    Logo,
    /// Print the embedded project license and third-party notices (also retained by self-updates).
    Licenses,
    /// Check GitHub for a stable release and atomically update an archive installation.
    Update {
        /// Report availability without installing anything.
        #[arg(long, conflicts_with = "output")]
        check: bool,
        /// Install to this NEW path instead of replacing the running binary.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Read PCAP/PCAPNG packets and link frames with an optional packet/application filter.
    Read {
        /// Input PCAP/PCAPNG capture file.
        file: PathBuf,
        #[command(flatten)]
        args: PacketArgs,
    },
    /// Aggregate TCP/UDP packets into bounded bidirectional flows.
    #[command(
        after_help = "Packet filters (before aggregation):\n  'src 192.0.2.10'                  tcpdump/BPF\n  'ip.src == 192.0.2.10'            Wireshark field alias\n\nFlow queries (same CQL as crepe query; after aggregation):\n  crepe flows traffic.pcap --query '* | sort packets desc | limit 10'\n  crepe flows traffic.pcap 'bytes > 1000 | sort bytes desc'\n  crepe flows traffic.pcap '* | count'\n  crepe flows traffic.pcap '* | group src.ip,dst.ip | sort count desc'\n\nCreate and reuse a flow database:\n  crepe flows traffic.pcap --store ./flows\n  crepe flows ./flows '* | sort bytes desc | limit 10'\n  crepe query ./flows '* | group src.ip | sort bytes desc'\n\nCorrelate by conversation identity (64-character flow_id from query output):\n  crepe query ./flows '* | select flow.id,src.ip,dst.ip,packets,bytes'\n  crepe trace ./flows FLOW_ID\nFor DNS/TLS/HTTP correlation use forensics FILE --store CASE instead; a flow-only\nstore contains flow records, not packet/application observations.\n\nFlows are bidirectional. In flow queries src/dst are canonical left/right endpoints.\nPacket prefilters can reduce counters; --query filters complete aggregated flows.\nQuery output is limited to 10,000 rows; --store retains all generated records."
    )]
    Flows(FlowArgs),
    /// Analyze DNS, TLS hello, HTTP/1.1 and SSH metadata after IP/TCP reassembly.
    Analyze {
        /// Input PCAP/PCAPNG capture file.
        file: PathBuf,
        #[arg(long, value_enum, default_value_t = Format::Json)]
        format: Format,
        /// UDP/TCP port used for DNS decoding.
        #[arg(long, default_value_t = 53)]
        dns_port: u16,
        /// Maximum simultaneously tracked TCP streams.
        #[arg(long, default_value_t = 1024, value_parser = clap::value_parser!(u32).range(1..=65536))]
        max_streams: u32,
        /// Maximum buffered reassembly bytes.
        #[arg(long, default_value_t = 4194304, value_parser = clap::value_parser!(u32).range(1..=268435456))]
        max_buffer_bytes: u32,
        /// Stream inactivity timeout in capture-timestamp seconds.
        #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..))]
        stream_idle: u64,
    },
    /// Deep network analysis: packets, flows, reassembly and application metadata.
    #[command(name = "inspect", aliases = ["chocolate", "choclate"])]
    Chocolate(RecipeArgs),
    /// Forensic case: persistent history, statistics, timeline and trace.
    #[command(
        long_about = "Analyze packets, flows and DNS/TLS/HTTP/SSH metadata. File input is fully processed before JSON Lines are printed (up to 10,000 observations). Use --store PATH to retain all observations, then crepe query PATH 'YOUR QUERY'. Live input streams observations as they become available. No arguments opens source selection. Suzette retains a forensic case by default in ./crepe-cases/case-*/history; --store chooses its location. Use timeline and trace to investigate the retained observations. Decoders are shared with chocolate, but the forensic history is retained automatically. The source capture is not copied.",
        after_help = "Examples:\n  crepe suzette traffic.pcap --store history\n  crepe query history '* | limit 20'\n  crepe suzette --interface lo --duration 10"
    )]
    #[command(name = "forensics", alias = "suzette")]
    Suzette(RecipeArgs),
    /// Run with your own configuration.
    #[command(name = "run", alias = "maison")]
    Maison(RecipeArgs),
    /// The full recipe: all currently implemented observations.
    #[command(name = "full", alias = "complete")]
    Complete(RecipeArgs),
    /// Run a configured live sensor under a service manager.
    Daemon {
        #[arg(long, default_value = "/etc/crepe/crepe.toml")]
        config: PathBuf,
        /// Maximum session length; service managers can restart at the boundary.
        #[arg(long, default_value_t = 86400, value_parser = clap::value_parser!(u64).range(1..=86400))]
        duration: u64,
    },
    /// Show the available recipes and their stored observations.
    Profiles,
    /// Import observations as an atomic Parquet batch.
    Ingest {
        /// Input PCAP/PCAPNG capture file.
        file: PathBuf,
        #[arg(long)]
        /// Historical store directory containing committed observation batches.
        store: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        sensor: Option<String>,
        /// Override the recipe selected in the configuration file.
        #[arg(long, value_enum)]
        profile: Option<Profile>,
    },
    /// Query historical observations with a CQL pipeline (JSON Lines).
    Query {
        /// Historical store directory containing committed observation batches.
        store: PathBuf,
        #[arg(default_value = "*")]
        /// Quoted historical filter/pipeline; defaults to all observations (bounded).
        cql: String,
    },
    /// Compact a stopped store into a NEW destination, optionally retaining recent rows.
    Compact {
        /// Historical store directory containing committed observation batches.
        store: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Earliest Unix timestamp in milliseconds; untimed observations are retained.
        #[arg(long, allow_hyphen_values = true)]
        since_ms: Option<i64>,
    },
    /// Show all observations for a conversation ID in time order.
    Trace {
        /// Existing historical store directory.
        store: PathBuf,
        /// 64-character hexadecimal conversation ID from query output.
        flow_id: String,
    },
    /// Show a chronological observation timeline.
    Timeline {
        /// Historical store directory containing committed observation batches.
        store: PathBuf,
        /// Maximum chronological observations to print (1..10000).
        #[arg(long,default_value_t=1000,value_parser=clap::value_parser!(u32).range(1..=10000))]
        limit: u32,
    },
    /// Validate and print effective configuration.
    Config {
        /// Optional TOML file layered over system/user configuration.
        file: Option<PathBuf>,
    },
    /// Receive NetFlow v5/v9 and IPFIX over UDP. Default: loopback only.
    #[command(visible_alias = "banane")]
    Collect {
        /// Local UDP bind address, optionally prefixed with udp://.
        #[arg(long, default_value = "127.0.0.1:2055", value_parser = parse_listen)]
        listen: std::net::SocketAddr,
        /// Wall-clock collection duration in seconds.
        #[arg(long,default_value_t=30,value_parser=clap::value_parser!(u64).range(1..=86400))]
        duration: u64,
        /// Stop after this many received datagrams, including templates and malformed input.
        #[arg(long,value_parser=clap::value_parser!(u64).range(1..))]
        count: Option<u64>,
        #[arg(long)]
        store: Option<PathBuf>,
        /// Sensor identity attached to stored export observations.
        #[arg(long, default_value = "local")]
        sensor: String,
    },
    #[cfg(feature = "live")]
    /// List libpcap capture interfaces.
    #[command(visible_alias = "interface")]
    Interfaces,
    #[cfg(feature = "live")]
    /// Capture live traffic (requires capture permissions). Alias: sucre.
    #[command(alias = "sucre")]
    Capture {
        #[arg(short, long)]
        interface: String,
        /// Explicit libpcap BPF prefilter (independent of CQL).
        #[arg(long)]
        bpf: Option<String>,
        /// Wall-clock capture duration in seconds; works on quiet interfaces too.
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=86400))]
        duration: u64,
        /// Stop after this many records delivered by libpcap, before CQL filtering.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        count: Option<u64>,
        #[arg(long)]
        /// Request promiscuous capture mode on the selected interface.
        promisc: bool,
        #[command(flatten)]
        args: PacketArgs,
    },
}
#[derive(Clone, Copy, ValueEnum)]
pub enum Format {
    Table,
    Json,
    Csv,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Profile {
    Sucre,
    #[value(alias = "choclate")]
    Chocolate,
    Banane,
    Suzette,
    Maison,
    Complete,
}
impl From<Profile> for crepe_engine::Profile {
    fn from(value: Profile) -> Self {
        match value {
            Profile::Sucre => Self::Sucre,
            Profile::Chocolate => Self::Chocolate,
            Profile::Banane => Self::Banane,
            Profile::Suzette => Self::Suzette,
            Profile::Maison => Self::Maison,
            Profile::Complete => Self::Complete,
        }
    }
}

#[derive(Args)]
pub(crate) struct RecipeArgs {
    /// Parallel live analysis workers; flow/stream budgets are divided across them.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=16))]
    pub workers: Option<u32>,
    /// Evaluate CQL over successive bounded live processing windows.
    #[arg(long, conflicts_with = "file")]
    pub query: Option<String>,
    /// Processing-window duration for --query (seconds).
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub query_interval: u64,
    /// Also collect NetFlow/IPFIX into the same live pipeline and historical store.
    #[arg(long, value_parser = parse_listen, conflicts_with = "file")]
    pub listen: Option<std::net::SocketAddr>,
    /// Capture file to analyze. Omit to select a source interactively.
    #[arg(conflicts_with = "interface")]
    pub file: Option<PathBuf>,
    /// Capture this interface, then analyze the captured traffic.
    #[arg(short, long)]
    pub interface: Option<String>,
    /// Live capture duration in seconds.
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=86400))]
    pub duration: u64,
    /// Historical store location. Suzette creates a persistent case by default; other file recipes use temporary storage.
    #[arg(long)]
    pub store: Option<PathBuf>,
    /// Load your own sensor, recipe and resource settings.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Suppress a protocol module's observations (repeatable).
    #[arg(long, value_parser = ["dns", "tls", "http", "ssh", "files", "notices"])]
    pub disable: Vec<String>,
    /// Re-enable a module suppressed by configuration (repeatable).
    #[arg(long, value_parser = ["dns", "tls", "http", "ssh", "files", "notices"])]
    pub enable: Vec<String>,
    /// Continue past malformed packets and emit anomaly.decode observations.
    #[arg(long)]
    pub tolerant: bool,
}

fn parse_listen(value: &str) -> std::result::Result<std::net::SocketAddr, String> {
    value
        .strip_prefix("udp://")
        .unwrap_or(value)
        .parse()
        .map_err(|_| "expected an IP:PORT or udp://IP:PORT address".into())
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum LogFormat {
    Text,
    Json,
}
