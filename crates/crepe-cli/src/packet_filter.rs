//! Keep the two filter grammars separate; BPF is compiled by libpcap itself.
use crate::args::FilterSyntax;
use crepe_capture::Record;
use crepe_core::Result;

pub(crate) struct Filter {
    cql: Option<crepe_query::Expr>,
    event: Option<crepe_query::event::Expr>,
    needs_application: bool,
    application: Option<String>,
    link: Option<String>,
    #[cfg(feature = "live")]
    bpf: Option<crepe_capture::live::PacketFilter>,
}
impl Filter {
    pub fn new(expression: Option<&str>, syntax: FilterSyntax) -> Result<Self> {
        let mut result = Self {
            cql: None,
            event: None,
            needs_application: false,
            application: None,
            link: None,
            #[cfg(feature = "live")]
            bpf: None,
        };
        let Some(expression) = expression else {
            return Ok(result);
        };
        if matches!(syntax, FilterSyntax::Auto) {
            let name = expression.trim().to_ascii_lowercase();
            if ["http", "dns", "tls", "ssh"].contains(&name.as_str()) {
                result.application = Some(name);
                return Ok(result);
            }
            if ["arp", "lldp", "eapol"].contains(&name.as_str()) {
                result.link = Some(name);
                return Ok(result);
            }
        }
        // Dotted CQL field names are unambiguous; preserve useful typed CQL errors.
        let cql_fields = [
            "ip.src",
            "ip.dst",
            "ip.addr",
            "ipv6.",
            "tcp.port",
            "tcp.srcport",
            "tcp.dstport",
            "udp.port",
            "udp.srcport",
            "udp.dstport",
        ]
        .iter()
        .any(|name| expression.contains(name))
            || (expression
                .split(|c: char| !c.is_ascii_alphanumeric())
                .any(|word| ["http", "dns", "tls", "ssh"].contains(&word))
                && crepe_query::parse(expression).is_ok())
            || ["tcp", "udp", "icmp", "icmpv6", "ip", "ipv6"].contains(&expression.trim())
            || expression.contains("src.")
            || expression.contains("dst.")
            || (expression
                .trim_start_matches([' ', '(', '!'])
                .starts_with("proto")
                && (expression.contains("==") || expression.contains("!=")));
        let cql_fields = cql_fields || crepe_query::event::parse(expression).is_ok();
        let is_cql = matches!(syntax, FilterSyntax::Cql)
            || (matches!(syntax, FilterSyntax::Auto) && cql_fields);
        if is_cql {
            match crepe_query::event::parse(expression) {
                Ok(expr) => {
                    result.event = Some(expr);
                    result.cql = crepe_query::parse(expression).ok();
                }
                Err(shared_error) => {
                    // Wireshark/tcpdump-style shorthand is a compatibility frontend.
                    let expr = crepe_query::parse(expression).map_err(|_| shared_error)?;
                    result.needs_application = expr.needs_application();
                    result.cql = Some(expr);
                }
            }
        } else {
            #[cfg(feature = "live")]
            {
                result.bpf = Some(crepe_capture::live::PacketFilter::new(expression)?);
            }
            #[cfg(not(feature = "live"))]
            return Err(crepe_core::Error::new("CREPE-CAP-005",
                "tcpdump/BPF filters require a build with --features live; use an official release or a CQL filter such as 'dst.port == 443'"));
        }
        Ok(result)
    }
    pub fn raw_matches(&mut self, record: &Record<'_>) -> Result<bool> {
        #[cfg(feature = "live")]
        if let Some(filter) = &mut self.bpf {
            return filter.matches(record);
        }
        let _ = record;
        Ok(true)
    }
    pub fn link_matches(&self, protocol: &str) -> bool {
        self.event.is_none()
            && self.cql.is_none()
            && self.application.is_none()
            && self.link.as_ref().is_none_or(|name| name == protocol)
    }
    pub fn view_matches(&self, view: &crepe_packet::PacketView<'_>) -> bool {
        self.link.is_none()
            && self
                .event
                .as_ref()
                .is_none_or(|e| e.matches_packet(&view.event))
            && (self.event.is_some()
                || self.cql.as_ref().is_none_or(|e| {
                    e.matches_application(
                        &view.event,
                        if self.needs_application {
                            crate::application::protocol(view)
                        } else {
                            None
                        },
                    )
                }))
            && self
                .application
                .as_ref()
                .is_none_or(|name| crate::application::protocol(view) == Some(name.as_str()))
    }
    #[cfg(feature = "live")]
    pub fn ethernet_prefilter(&self) -> Option<String> {
        self.cql.as_ref().and_then(|e| e.ethernet_prefilter())
    }
}
