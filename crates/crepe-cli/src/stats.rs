//! Streaming, exact capture statistics with explicitly bounded group cardinality.
use crate::{args::FilterSyntax, packet_filter::Filter};
use crepe_core::{Error, Result};
use serde::Serialize;
use std::{collections::BTreeMap, io::Write, path::PathBuf};

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum Format {
    Table,
    Markdown,
    Csv,
    Json,
}
#[derive(clap::Args)]
pub struct Args {
    /// PCAP or PCAPNG input. No store/import or capture permissions required.
    pub file: PathBuf,
    /// summary, hierarchy, protocols, top-talkers, endpoints, conversations, ports, flags,
    /// arp/syn/syn-ack/fin/rst, or a quoted packet filter to count.
    pub report: Option<String>,
    /// TShark-style report alias: io,phs; endpoints,ip/ipv6; conv,ip/ipv6; io,stat,0.
    #[arg(short = 'z', conflicts_with = "report")]
    pub statistic: Option<String>,
    /// Filter before counting/grouping. Same CQL/BPF syntax as read.
    #[arg(short = 'f', long, visible_alias = "where")]
    pub filter: Option<String>,
    #[arg(long, value_enum, default_value_t = FilterSyntax::Auto)]
    pub filter_syntax: FilterSyntax,
    /// Largest ranking groups to show; all groups still contribute to totals.
    #[arg(short = 'n', long, default_value_t = 20, value_parser = clap::value_parser!(u32).range(1..=65536))]
    pub top: u32,
    /// Rank groups by wire bytes or packets, descending (ties sort by name).
    #[arg(long, value_parser = ["bytes", "packets"], default_value = "bytes")]
    pub sort: String,
    /// Stop after N matching packets, before grouping (not N report rows).
    #[arg(short = 'c', long, value_parser = clap::value_parser!(u64).range(1..))]
    pub limit: Option<u64>,
    /// Exact group budget. Exceeding it fails instead of silently approximating.
    #[arg(long, default_value_t = 65536, value_parser = clap::value_parser!(u32).range(1..=65536))]
    pub max_groups: u32,
    #[arg(long, value_enum, default_value_t = Format::Table)]
    pub format: Format,
    /// Publish the completed report to a NEW file; never overwrites.
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
    /// Skip malformed packets and report the skipped count; container errors still fail.
    #[arg(long)]
    pub tolerant: bool,
}
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Summary,
    Hierarchy,
    Protocols,
    Talkers,
    Endpoints,
    Conversations,
    Ports,
    Flags,
    Count,
}
fn mode(text: &str) -> (Mode, Option<&str>) {
    match text {
        "summary" | "io,stat,0" => (Mode::Summary, None),
        "hierarchy" | "protocol-hierarchy" | "protocol hierarchy" | "io,phs" => {
            (Mode::Hierarchy, None)
        }
        "protocols" | "protocol" => (Mode::Protocols, None),
        "top-talkers" | "talkers" | "top talkers" => (Mode::Talkers, None),
        "endpoints" | "endpoints,ip" | "endpoints,ipv6" => (Mode::Endpoints, None),
        "conversations" | "conv,ip" | "conv,ipv6" => (Mode::Conversations, None),
        "ports" => (Mode::Ports, None),
        "flags" | "tcp-flags" => (Mode::Flags, None),
        other => (
            Mode::Count,
            Some(other.strip_prefix("count ").unwrap_or(other).trim()),
        ),
    }
}
#[derive(Default, Clone, Copy, Serialize)]
struct Counter {
    packets: u64,
    bytes: u64,
}
impl Counter {
    fn add(&mut self, bytes: u32) -> Result<()> {
        self.packets = self
            .packets
            .checked_add(1)
            .ok_or_else(|| error("packet count overflow"))?;
        self.bytes = self
            .bytes
            .checked_add(u64::from(bytes))
            .ok_or_else(|| error("byte count overflow"))?;
        Ok(())
    }
}
fn error(message: impl std::fmt::Display) -> Error {
    Error::new("CREPE-STATS-001", message)
}
fn flag(name: &str, flags: Option<u8>) -> bool {
    flags.is_some_and(|v| match name {
        "syn" => v & 2 != 0,
        "syn-only" => v & 0x12 == 2,
        "syn-ack" => v & 0x12 == 0x12,
        "ack" => v & 0x10 != 0,
        "fin" => v & 1 != 0,
        "rst" => v & 4 != 0,
        "psh" => v & 8 != 0,
        "urg" => v & 0x20 != 0,
        "ece" => v & 0x40 != 0,
        "cwr" => v & 0x80 != 0,
        _ => false,
    })
}
const FLAGS: &[&str] = &[
    "syn", "syn-only", "syn-ack", "ack", "fin", "rst", "psh", "urg", "ece", "cwr",
];
fn link_name(link: u32) -> String {
    match link {
        1 => "ethernet".into(),
        0 | 108 => "loopback".into(),
        113 => "sll".into(),
        276 => "sll2".into(),
        101 | 228 | 229 => "raw-ip".into(),
        n => format!("linktype-{n}"),
    }
}
fn add(groups: &mut BTreeMap<String, Counter>, key: String, bytes: u32, budget: u32) -> Result<()> {
    if groups.len() >= budget as usize && !groups.contains_key(&key) {
        return Err(error(
            "exact group budget exceeded; narrow --filter or increase --max-groups (maximum 65536)",
        ));
    }
    groups.entry(key).or_default().add(bytes)
}
#[derive(Serialize)]
struct Row {
    name: String,
    packets: u64,
    bytes: u64,
    percent_packets: f64,
}
#[derive(Serialize)]
struct Report {
    schema_version: u16,
    input_file: String,
    report: String,
    filter: Option<String>,
    records_read: u64,
    matched_packets: u64,
    matched_bytes: u64,
    malformed_skipped: u64,
    groups_total: usize,
    rows_omitted: usize,
    byte_basis: &'static str,
    classification: &'static str,
    rows: Vec<Row>,
}
pub fn run(args: Args) -> Result<()> {
    let title = args
        .statistic
        .as_deref()
        .or(args.report.as_deref())
        .unwrap_or("summary");
    let (mode, expression) = mode(title);
    let family = match title {
        "endpoints,ip" | "conv,ip" => Some(true),
        "endpoints,ipv6" | "conv,ipv6" => Some(false),
        _ => None,
    };
    if args.statistic.is_some() && mode == Mode::Count {
        return Err(error(
            "unsupported -z report; use io,phs; endpoints,ip; conv,ip; or io,stat,0 (see stats -h)",
        ));
    }
    let flag_filter = expression.filter(|s| FLAGS.contains(s));
    let mut selection = Filter::new(args.filter.as_deref(), args.filter_syntax)?;
    let mut count_filter = Filter::new(
        expression.filter(|_| flag_filter.is_none()),
        args.filter_syntax,
    )?;
    let mut groups = BTreeMap::new();
    if mode == Mode::Count {
        groups.insert(
            expression.unwrap_or("count").to_string(),
            Counter::default(),
        );
    }
    if mode == Mode::Flags {
        for name in FLAGS {
            groups.insert((*name).into(), Counter::default());
        }
    }
    if groups.len() > args.max_groups as usize {
        return Err(error("report requires more groups; increase --max-groups"));
    }
    let (mut records, mut malformed) = (0_u64, 0_u64);
    let mut total = Counter::default();
    crepe_capture::read_records(crepe_capture::open(&args.file)?, |record| {
        records += 1;
        if !selection.raw_matches(&record)? || !count_filter.raw_matches(&record)? {
            return Ok(true);
        }
        let decoded = (|| {
            let link = crate::link_display::decode(&record)?;
            let view = if link.is_none() {
                crepe_packet::decode_view(record.data, record.header.clone(), record.linktype)?
            } else {
                None
            };
            Ok::<_, Error>((link, view))
        })();
        let (link, view) = match decoded {
            Ok(value) => value,
            Err(e) if args.tolerant && e.code == "CREPE-PKT-001" => {
                malformed += 1;
                return Ok(true);
            }
            Err(e) => return Err(e),
        };
        let selected = if let Some(v) = &view {
            family.is_none_or(|ipv4| v.event.src.ip.is_ipv4() == ipv4)
                && selection.view_matches(v)
                && count_filter.view_matches(v)
                && flag_filter.is_none_or(|n| flag(n, v.event.tcp_flags))
        } else {
            let proto = link.as_ref().map_or("unknown", |l| l.proto);
            family.is_none()
                && selection.link_matches(proto)
                && count_filter.link_matches(proto)
                && flag_filter.is_none()
        };
        if !selected {
            return Ok(true);
        }
        let bytes = record.header.original_len;
        total.add(bytes)?;
        let mut path = Vec::new();
        if matches!(mode, Mode::Summary | Mode::Hierarchy | Mode::Protocols) {
            path.push(link_name(record.linktype));
            if let Some(v) = &view {
                for _ in &v.event.vlans {
                    path.push("vlan".into());
                }
                path.push(
                    if v.event.src.ip.is_ipv4() {
                        "ipv4"
                    } else {
                        "ipv6"
                    }
                    .into(),
                );
                path.push(v.event.proto.to_string());
                if let Some(app) = crate::application::protocol(v) {
                    path.push(app.into());
                }
            } else if let Some(l) = &link {
                for _ in &l.vlans {
                    path.push("vlan".into());
                }
                path.push(if l.proto == "ethernet" {
                    format!("ethertype-0x{:04x}", l.ether_type)
                } else {
                    l.proto.into()
                });
            } else {
                path.push("unknown".into());
            }
        }
        let mut keys = Vec::new();
        match mode {
            Mode::Count => keys.push(expression.unwrap().into()),
            Mode::Hierarchy => {
                for depth in 1..=path.len() {
                    keys.push(path[..depth].join(" > "));
                }
            }
            Mode::Protocols => keys.extend(path.iter().skip(1).cloned()),
            Mode::Summary => {
                keys.push("all matched packets".into());
                keys.extend(path.iter().skip(1).cloned());
                if let Some(v) = &view {
                    if v.event.fragmented {
                        keys.push("ip fragments".into());
                    }
                }
            }
            Mode::Flags => {
                if let Some(v) = &view {
                    for name in FLAGS {
                        if flag(name, v.event.tcp_flags) {
                            keys.push((*name).into());
                        }
                    }
                }
            }
            Mode::Talkers | Mode::Endpoints | Mode::Conversations | Mode::Ports => {
                if let Some(v) = &view {
                    let src = v.event.src.ip.to_string();
                    let dst = v.event.dst.ip.to_string();
                    match mode {
                        Mode::Talkers => keys.push(src),
                        Mode::Endpoints => {
                            keys.push(src);
                            keys.push(dst);
                        }
                        Mode::Conversations => {
                            let mut pair = [src, dst];
                            pair.sort();
                            keys.push(format!("{} <-> {}", pair[0], pair[1]));
                        }
                        Mode::Ports => {
                            if let Some(port) = v.event.dst.port {
                                keys.push(format!("{}/{port}", v.event.proto));
                            }
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }
        // One packet contributes once to each node/endpoint, including loopback and stacked VLANs.
        keys.sort();
        keys.dedup();
        for key in keys {
            add(&mut groups, key, bytes, args.max_groups)?;
        }
        Ok(args.limit.is_none_or(|limit| total.packets < limit))
    })?;
    let group_count = groups.len();
    let mut rows: Vec<Row> = groups
        .into_iter()
        .map(|(name, c)| Row {
            name,
            packets: c.packets,
            bytes: c.bytes,
            percent_packets: if total.packets == 0 {
                0.0
            } else {
                c.packets as f64 * 100.0 / total.packets as f64
            },
        })
        .collect();
    if matches!(
        mode,
        Mode::Talkers | Mode::Endpoints | Mode::Conversations | Mode::Ports
    ) {
        rows.sort_by(|a, b| {
            (if args.sort == "bytes" {
                b.bytes.cmp(&a.bytes)
            } else {
                b.packets.cmp(&a.packets)
            })
            .then(a.name.cmp(&b.name))
        });
        rows.truncate(args.top as usize);
    }
    let report = Report {
        schema_version: 1,
        input_file: args.file.display().to_string(),
        report: title.into(),
        filter: args.filter.clone(),
        records_read: records,
        matched_packets: total.packets,
        matched_bytes: total.bytes,
        malformed_skipped: malformed,
        groups_total: group_count,
        rows_omitted: group_count - rows.len(),
        byte_basis: "original frame length, including captured link headers",
        classification:
            "packet-local; no TCP/IP reassembly; protocol/flag/endpoint rows may overlap",
        rows,
    };
    if let Some(path) = &args.output {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        let mut file = tempfile::NamedTempFile::new_in(parent).map_err(error)?;
        render(&report, args.format, &mut file)?;
        file.as_file().sync_all().map_err(error)?;
        file.persist_noclobber(path).map_err(error)?;
    } else {
        let mut out = std::io::BufWriter::new(std::io::stdout().lock());
        render(&report, args.format, &mut out)?;
        out.flush().map_err(crate::output_error)?;
    }
    Ok(())
}
fn render(r: &Report, format: Format, out: &mut impl Write) -> Result<()> {
    let io = |e| crate::output_error(e);
    if matches!(format, Format::Json) {
        serde_json::to_writer_pretty(&mut *out, r).map_err(|e| {
            if e.io_error_kind() == Some(std::io::ErrorKind::BrokenPipe) {
                Error::new("CREPE-IO-PIPE", e)
            } else {
                error(e)
            }
        })?;
        return writeln!(out).map_err(io);
    }
    let markdown = matches!(format, Format::Markdown);
    if matches!(format, Format::Csv) {
        writeln!(out,"name,packets,bytes,percent_packets,matched_packets,matched_bytes,records_read,malformed_skipped,rows_omitted").map_err(io)?;
        for row in &r.rows {
            writeln!(
                out,
                "\"{}\",{},{},{:.2},{},{},{},{},{}",
                row.name.replace('"', "\"\""),
                row.packets,
                row.bytes,
                row.percent_packets,
                r.matched_packets,
                r.matched_bytes,
                r.records_read,
                r.malformed_skipped,
                r.rows_omitted
            )
            .map_err(io)?;
        }
        return Ok(());
    }
    writeln!(
        out,
        "Crepe statistics: {}\n",
        crate::application::text(r.report.as_bytes())
    )
    .map_err(io)?;
    writeln!(
        out,
        "Capture: {}",
        crate::application::text(r.input_file.as_bytes())
    )
    .map_err(io)?;
    if let Some(f) = &r.filter {
        writeln!(out, "Filter: {}", crate::application::text(f.as_bytes())).map_err(io)?;
    }
    writeln!(out,"Matched: {} packets / {} bytes; read: {}; malformed skipped: {}; omitted groups: {}.\nBytes: original frame length. Classification: packet-local; rows may overlap.\n",r.matched_packets,r.matched_bytes,r.records_read,r.malformed_skipped,r.rows_omitted).map_err(io)?;
    let width = r
        .rows
        .iter()
        .map(|v| v.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    if markdown {
        writeln!(
            out,
            "| Name | Packets | Bytes | % matched packets |\n| --- | ---: | ---: | ---: |"
        )
        .map_err(io)?;
    } else {
        writeln!(
            out,
            "{:width$} {:>12} {:>16} {:>10}",
            "NAME", "PACKETS", "BYTES", "PACKET %"
        )
        .map_err(io)?;
    }
    for row in &r.rows {
        let name = crate::application::text(row.name.as_bytes());
        if markdown {
            writeln!(
                out,
                "| {} | {} | {} | {:.2} |",
                name.replace('|', "\\|")
                    .replace('<', "&lt;")
                    .replace('>', "&gt;"),
                row.packets,
                row.bytes,
                row.percent_packets
            )
            .map_err(io)?;
        } else {
            writeln!(
                out,
                "{:width$} {:>12} {:>16} {:>9.2}%",
                name, row.packets, row.bytes, row.percent_packets
            )
            .map_err(io)?;
        }
    }
    Ok(())
}
