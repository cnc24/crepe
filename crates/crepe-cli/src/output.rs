use crate::{output_error, Format};
use crepe_core::{Error, Result};
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
        let flow_header = crate::flow_display::header();
        let text = match (self.format, flows) {
            (Format::Json, _) => return Ok(()),
            (Format::Table, false) => "TIME (UTC)          SOURCE > DESTINATION: PROTOCOL DETAILS (absolute TCP seq/ack)",
            (Format::Table, true) => &flow_header,
            (Format::Csv, false) => "sequence,timestamp_ns,src_ip,src_port,dst_ip,dst_port,proto,captured_len,original_len,section,interface,vlans,tcp_flags,src_mac,dst_mac,ether_type,linktype",
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
    pub fn packet(&mut self, view: &crepe_packet::PacketView<'_>) -> Result<()> {
        let p = &view.event;
        let port = |p: Option<u16>| p.map(|n| n.to_string()).unwrap_or_default();
        match self.format {
            Format::Json => self.json(p),
            Format::Table => {
                writeln!(self.writer, "{}", crate::packet_display::line(view)).map_err(output_error)
            }
            Format::Csv => writeln!(
                self.writer,
                "{},{},{},{},{},{},{},{},{},{},{},{},{},,,,",
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
    pub fn packet_details(
        &mut self,
        record: &crepe_capture::Record<'_>,
        view: &crepe_packet::PacketView<'_>,
        level: u8,
    ) -> Result<()> {
        if let Some((ip, _)) = crepe_packet::network(record.data, record.linktype)? {
            if ip[0] >> 4 == 4 {
                writeln!(self.writer,"    IPv4 ttl {}, id {}, tos 0x{:02x}, flags/offset 0x{:04x}, checksum 0x{:04x}, length {}",
                    ip[8],u16::from_be_bytes([ip[4],ip[5]]),ip[1],u16::from_be_bytes([ip[6],ip[7]]),u16::from_be_bytes([ip[10],ip[11]]),ip.len()).map_err(output_error)?;
            } else {
                writeln!(
                    self.writer,
                    "    IPv6 hop limit {}, next header {}, length {}",
                    ip[7],
                    ip[6],
                    ip.len()
                )
                .map_err(output_error)?;
            }
        }
        writeln!(
            self.writer,
            "    record {}, LINKTYPE {}, captured {} / wire {} bytes",
            record.header.sequence,
            record.linktype,
            record.header.captured_len,
            record.header.original_len
        )
        .map_err(output_error)?;
        if level >= 2 && crate::application::http_line(view.payload).is_some() {
            let end = view
                .payload
                .windows(4)
                .position(|b| b == b"\r\n\r\n")
                .map(|n| n + 4)
                .unwrap_or(view.payload.len());
            self.payload(&view.payload[..end], true, false)?;
        }
        Ok(())
    }
    pub fn payload(&mut self, bytes: &[u8], ascii: bool, hex: bool) -> Result<()> {
        if ascii && !bytes.is_empty() {
            for line in crate::application::text(bytes).lines() {
                writeln!(self.writer, "    {line}").map_err(output_error)?;
            }
        }
        if hex {
            for (i, row) in bytes.chunks(16).enumerate() {
                let encoded = row
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let printable: String = row
                    .iter()
                    .map(|&b| {
                        if (32..=126).contains(&b) {
                            char::from(b)
                        } else {
                            '.'
                        }
                    })
                    .collect();
                writeln!(self.writer, "    {:04x}  {encoded:47}  {printable}", i * 16)
                    .map_err(output_error)?;
            }
        }
        Ok(())
    }
    pub fn link(&mut self, p: &crate::link_display::LinkRecord<'_>) -> Result<()> {
        match self.format {
            Format::Json => self.json(p),
            Format::Table => writeln!(
                self.writer,
                "{} {} > {}: {} {}, wire {} bytes{}",
                crate::packet_display::timestamp(p.header.timestamp_ns.as_deref()),
                p.src_mac.as_deref().unwrap_or("link"),
                p.dst_mac.as_deref().unwrap_or("link"),
                p.proto.to_uppercase(),
                p.details,
                p.header.original_len,
                if p.vlans.is_empty() {
                    String::new()
                } else {
                    format!(", vlan {:?}", p.vlans)
                }
            )
            .map_err(output_error),
            Format::Csv => writeln!(
                self.writer,
                "{},{},,,,,{},{},{},{},{},{},,{},{},{},{}",
                p.header.sequence,
                p.header.timestamp_ns.as_deref().unwrap_or(""),
                p.proto,
                p.header.captured_len,
                p.header.original_len,
                p.header.section,
                p.header.interface,
                vlans(&p.vlans),
                p.src_mac.as_deref().unwrap_or(""),
                p.dst_mac.as_deref().unwrap_or(""),
                p.ether_type,
                p.linktype
            )
            .map_err(output_error),
        }
    }
    pub fn query_value(&mut self, value: &serde_json::Value) -> Result<()> {
        self.json(value)
    }
    pub fn query_columns(&mut self, value: &serde_json::Value, header: bool) -> Result<()> {
        let row = value
            .as_object()
            .ok_or_else(|| Error::new("CREPE-CQL-001", "expected a query result object"))?;
        let csv = matches!(self.format, Format::Csv);
        let quote = |s: String| {
            if csv {
                format!("\"{}\"", s.replace('"', "\"\""))
            } else {
                s
            }
        };
        let separator = if csv { "," } else { "\t" };
        if header {
            writeln!(
                self.writer,
                "{}",
                row.keys()
                    .map(|s| quote(s.clone()))
                    .collect::<Vec<_>>()
                    .join(separator)
            )
            .map_err(output_error)?;
        }
        writeln!(
            self.writer,
            "{}",
            row.values()
                .map(|v| quote(v.to_string()))
                .collect::<Vec<_>>()
                .join(separator)
        )
        .map_err(output_error)
    }
    pub fn flow(&mut self, f: &FlowRecord, details: bool) -> Result<()> {
        let reason =
            serde_json::to_value(f.end_reason).map_err(|e| Error::new("CREPE-IO-002", e))?;
        let reason = reason.as_str().unwrap_or("unknown");
        match self.format {
            Format::Json => self.json(f),
            Format::Table => writeln!(
                self.writer,
                "{}",
                if details {
                    crate::flow_display::summary(f)
                } else {
                    crate::flow_display::row(f)
                }
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
