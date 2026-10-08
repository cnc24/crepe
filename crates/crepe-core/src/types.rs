use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Other(u8),
}
impl Protocol {
    pub fn from_number(n: u8) -> Self {
        match n {
            6 => Self::Tcp,
            17 => Self::Udp,
            1 => Self::Icmp,
            58 => Self::Icmpv6,
            n => Self::Other(n),
        }
    }
}
impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => f.write_str("tcp"),
            Self::Udp => f.write_str("udp"),
            Self::Icmp => f.write_str("icmp"),
            Self::Icmpv6 => f.write_str("icmpv6"),
            Self::Other(n) => write!(f, "{n}"),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: Option<u16>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    Packet,
    #[serde(rename = "flow.end")]
    FlowEnd,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventHeader {
    pub schema_version: u16,
    pub event_type: EventType,
    /// One-based capture record number, including skipped non-IP frames.
    pub sequence: u64,
    pub section: u32,
    pub interface: u32,
    /// Unix nanoseconds as a decimal string (lossless in JSON clients); None for SPB.
    pub timestamp_ns: Option<String>,
    pub captured_len: u32,
    pub original_len: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketEvent {
    pub header: EventHeader,
    pub src: Endpoint,
    pub dst: Endpoint,
    pub proto: Protocol,
    pub fragmented: bool,
    pub vlans: Vec<u16>,
    /// TCP flags byte (FIN through CWR), absent for non-TCP or fragmented packets.
    pub tcp_flags: Option<u8>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
}
