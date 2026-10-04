use crate::{output_error, Format};
use crepe_core::{Error, PacketEvent, Result};
use crepe_flow::FlowRecord;
use serde::Serialize;
use std::io::Write;

pub struct Output<W: Write> {
    writer: W,
    format: Format,
}
impl<W: Write> Output<W> {
    pub fn new(writer: W, format: Format) -> Self {
        Self { writer, format }
    }
    pub fn header(&mut self, flows: bool) -> Result<()> {
        let text = match (self.format, flows) {
            (Format::Json, _) => return Ok(()),
            (Format::Table, false) => "#      UNIX_NS                SRC.IP                                  PORT  DST.IP                                  PORT  PROTO   BYTES",
            (Format::Table, true) => "FLOW_ID             PROTO A                                             B                                             PKTS_A PKTS_B BYTES_A BYTES_B REASON",
            (Format::Csv, false) => "sequence,timestamp_ns,src_ip,src_port,dst_ip,dst_port,proto,captured_len,original_len,section,interface,vlans,tcp_flags",
            (Format::Csv, true) => "flow_id,start_ns,end_ns,a_ip,a_port,b_ip,b_port,proto,packets_a,packets_b,bytes_a,bytes_b,tcp_flags_a,tcp_flags_b,section,interface,vlans,end_reason",
        };
        writeln!(self.writer, "{text}").map_err(output_error)
    }
    fn json(&mut self, value: &impl Serialize) -> Result<()> {
        serde_json::to_writer(&mut self.writer, value).map_err(|e| {
            Error::new(
                if e.io_error_kind() == Some(std::io::ErrorKind::BrokenPipe) {
                    "CREPE-IO-PIPE"
                } else {
                    "CREPE-IO-002"
                },
                e,
            )
        })?;
        writeln!(self.writer).map_err(output_error)
    }
    pub fn packet(&mut self, p: &PacketEvent) -> Result<()> {
        let port = |p: Option<u16>| p.map(|n| n.to_string()).unwrap_or_default();
        match self.format {
            Format::Json => self.json(p),
            Format::Table => writeln!(
                self.writer,
                "{:<6} {:<22} {:<39} {:<5} {:<39} {:<5} {:<7} {}",
                p.header.sequence,
                p.header.timestamp_ns.as_deref().unwrap_or("-"),
                p.src.ip.to_string(),
                port(p.src.port),
                p.dst.ip.to_string(),
                port(p.dst.port),
                p.proto.to_string(),
                p.header.original_len
            )
            .map_err(output_error),
            Format::Csv => writeln!(
                self.writer,
                "{},{},{},{},{},{},{},{},{},{},{},{},{}",
                p.header.sequence,
                p.header.timestamp_ns.as_deref().unwrap_or(""),
                p.src.ip,
                port(p.src.port),
                p.dst.ip,
                port(p.dst.port),
                p.proto,
                p.header.captured_len,
                p.header.original_len,
                p.header.section,
                p.header.interface,
                vlans(&p.vlans),
                p.tcp_flags.map(|n| n.to_string()).unwrap_or_default()
            )
            .map_err(output_error),
        }
    }
    pub fn flow(&mut self, f: &FlowRecord) -> Result<()> {
        let reason =
            serde_json::to_value(f.end_reason).map_err(|e| Error::new("CREPE-IO-002", e))?;
        let reason = reason.as_str().unwrap_or("unknown");
        match self.format {
            Format::Json => self.json(f),
            Format::Table => writeln!(
                self.writer,
                "{} {:<5} {:<45} {:<45} {:<6} {:<6} {:<7} {:<7} {}",
                f.flow_id,
                f.proto.to_string(),
                endpoint(&f.a),
                endpoint(&f.b),
                f.packets_a,
                f.packets_b,
                f.bytes_a,
                f.bytes_b,
                reason
            )
            .map_err(output_error),
            Format::Csv => writeln!(
                self.writer,
                "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                f.flow_id,
                f.start_ns,
                f.end_ns,
                f.a.ip,
                f.a.port.unwrap(),
                f.b.ip,
                f.b.port.unwrap(),
                f.proto,
                f.packets_a,
                f.packets_b,
                f.bytes_a,
                f.bytes_b,
                f.tcp_flags_a,
                f.tcp_flags_b,
                f.section,
                f.interface,
                vlans(&f.vlans),
                reason
            )
            .map_err(output_error),
        }
    }
    pub fn analysis_header(&mut self) -> Result<()> {
        match self.format {
            Format::Json => Ok(()),
            Format::Table => writeln!(self.writer, "# TYPE SOURCE DESTINATION NAME / ANOMALY")
                .map_err(output_error),
            Format::Csv => writeln!(
                self.writer,
                "sequence,event_type,src_ip,src_port,dst_ip,dst_port,dns_id,name,anomaly_code"
            )
            .map_err(output_error),
        }
    }
    pub fn analysis(&mut self, e: &crepe_analysis::Event) -> Result<()> {
        if matches!(self.format, Format::Json) {
            return self.json(e);
        }
        let kind = match e.event_type {
            crepe_analysis::Kind::DnsQuery => "dns.query",
            crepe_analysis::Kind::DnsResponse => "dns.response",
            crepe_analysis::Kind::Anomaly => "anomaly",
            crepe_analysis::Kind::Protocol => {
                e.protocol.as_ref().map(|p| p.kind()).unwrap_or("protocol")
            }
        };
        let name = e
            .dns
            .as_ref()
            .and_then(|dns| dns.questions.first())
            .map(|q| q.name.as_str())
            .unwrap_or("");
        let protocol = e
            .protocol
            .as_ref()
            .map(|p| serde_json::to_string(p).unwrap_or_default())
            .unwrap_or_default();
        let name = if protocol.is_empty() {
            name
        } else {
            protocol.as_str()
        };
        let code = e.anomaly.as_ref().map(|a| a.code).unwrap_or("");
        let p = &e.packet;
        match self.format {
            Format::Table => writeln!(
                self.writer,
                "{} {} {} {} {} {}",
                p.header.sequence,
                kind,
                endpoint(&p.src),
                endpoint(&p.dst),
                name,
                code
            )
            .map_err(output_error),
            Format::Csv => writeln!(
                self.writer,
                "{},{},{},{},{},{},{},{},{}",
                p.header.sequence,
                kind,
                p.src.ip,
                p.src.port.unwrap_or(0),
                p.dst.ip,
                p.dst.port.unwrap_or(0),
                e.dns.as_ref().map(|d| d.id.to_string()).unwrap_or_default(),
                format_args!("\"{}\"", name.replace('"', "\"\"")),
                code
            )
            .map_err(output_error),
            Format::Json => unreachable!(),
        }
    }
    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush().map_err(output_error)
    }
}
fn vlans(v: &[u16]) -> String {
    v.iter().map(u16::to_string).collect::<Vec<_>>().join(";")
}
fn endpoint(e: &crepe_core::Endpoint) -> String {
    if e.ip.is_ipv6() {
        format!(
            "[{}]:{}",
            e.ip,
            e.port.map(|p| p.to_string()).unwrap_or_else(|| "-".into())
        )
    } else {
        format!(
            "{}:{}",
            e.ip,
            e.port.map(|p| p.to_string()).unwrap_or_else(|| "-".into())
        )
    }
}
