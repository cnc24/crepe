use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    name = "crepe",
    version,
    about = "Bon appétit! Packet capture and flow explorer"
)]
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
#[derive(Args)]
pub(crate) struct PacketArgs {
    /// CQL predicate, applied before output and export.
    pub filter: Option<String>,
    /// Skip malformed packet payloads; capture-container and I/O errors still stop.
    #[arg(long)]
    pub tolerant: bool,
    #[arg(long, value_enum, default_value_t = Format::Table)]
    pub format: Format,
    /// Stop after this many matching IP packets.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub limit: Option<u64>,
    /// Write matching packet bytes to a new PCAP (never overwrites).
    #[arg(short, long)]
    pub write: Option<PathBuf>,
}
#[derive(Subcommand)]
pub(crate) enum Command {
    /// Read PCAP/PCAPNG and apply an optional CQL filter.
    Read {
        file: PathBuf,
        #[command(flatten)]
        args: PacketArgs,
    },
    /// Aggregate TCP/UDP packets into bounded bidirectional flows.
    Flows {
        file: PathBuf,
        /// Packet filter, applied BEFORE aggregation; counters cover selected packets only.
        filter: Option<String>,
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
        #[arg(long, default_value_t = 65536, value_parser = clap::value_parser!(u32).range(1..=1_000_000))]
        max_flows: u32,
        #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..))]
        tcp_idle: u64,
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
        udp_idle: u64,
        #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..))]
        active_timeout: u64,
    },
    /// Analyze DNS, TLS hello, HTTP/1.1 and SSH metadata after IP/TCP reassembly.
    Analyze {
        file: PathBuf,
        #[arg(long, value_enum, default_value_t = Format::Json)]
        format: Format,
        #[arg(long, default_value_t = 53)]
        dns_port: u16,
        #[arg(long, default_value_t = 1024, value_parser = clap::value_parser!(u32).range(1..=65536))]
        max_streams: u32,
        #[arg(long, default_value_t = 4194304, value_parser = clap::value_parser!(u32).range(1..=268435456))]
        max_buffer_bytes: u32,
        #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..))]
        stream_idle: u64,
    },
    /// Deep network analysis: packets, flows, reassembly and application metadata.
    Nutella(RecipeArgs),
    /// Forensics: analyze a capture and query its historical observations.
    Suzette(RecipeArgs),
    /// Run with your own configuration.
    Maison(RecipeArgs),
    /// The full recipe: all currently implemented observations.
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
        file: PathBuf,
        #[arg(long)]
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
        store: PathBuf,
        #[arg(default_value = "*")]
        cql: String,
    },
    /// Compact a stopped store into a NEW destination, optionally retaining recent rows.
    Compact {
        store: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Earliest Unix timestamp in milliseconds; untimed observations are retained.
        #[arg(long, allow_hyphen_values = true)]
        since_ms: Option<i64>,
    },
    /// Show all observations for a conversation ID in time order.
    Trace { store: PathBuf, flow_id: String },
    /// Show a chronological observation timeline.
    Timeline {
        store: PathBuf,
        #[arg(long,default_value_t=1000,value_parser=clap::value_parser!(u32).range(1..=10000))]
        limit: u32,
    },
    /// Validate and print effective configuration.
    Config { file: Option<PathBuf> },
    /// Receive NetFlow v5/v9 and IPFIX over UDP. Default: loopback only.
    #[command(visible_alias = "banane")]
    Collect {
        #[arg(long, default_value = "127.0.0.1:2055", value_parser = parse_listen)]
        listen: std::net::SocketAddr,
        #[arg(long,default_value_t=30,value_parser=clap::value_parser!(u64).range(1..=86400))]
        duration: u64,
        #[arg(long,value_parser=clap::value_parser!(u64).range(1..))]
        count: Option<u64>,
        #[arg(long)]
        store: Option<PathBuf>,
        #[arg(long, default_value = "local")]
        sensor: String,
    },
    #[cfg(feature = "live")]
    /// List libpcap capture interfaces.
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
    Nutella,
    Banane,
    Suzette,
    Maison,
    Complete,
}
impl From<Profile> for crepe_engine::Profile {
    fn from(value: Profile) -> Self {
        match value {
            Profile::Sucre => Self::Sucre,
            Profile::Nutella => Self::Nutella,
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
    /// Keep observations in this historical store. Otherwise use temporary storage.
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
