//! Keep the two filter grammars separate; BPF is compiled by libpcap itself.
use crate::args::FilterSyntax;
use crepe_capture::Record;
use crepe_core::{PacketEvent, Result};

pub(crate) struct Filter {
    cql: Option<crepe_query::Expr>,
    #[cfg(feature = "live")]
    bpf: Option<crepe_capture::live::PacketFilter>,
}
impl Filter {
    pub fn new(expression: Option<&str>, syntax: FilterSyntax) -> Result<Self> {
        let mut result = Self {
            cql: None,
            #[cfg(feature = "live")]
            bpf: None,
        };
        let Some(expression) = expression else {
            return Ok(result);
        };
        // Dotted CQL field names are unambiguous; preserve useful typed CQL errors.
        let cql_fields = expression.contains("src.")
            || expression.contains("dst.")
            || (expression
                .trim_start_matches([' ', '(', '!'])
                .starts_with("proto")
                && (expression.contains("==") || expression.contains("!=")));
        let is_cql = matches!(syntax, FilterSyntax::Cql)
            || (matches!(syntax, FilterSyntax::Auto) && cql_fields);
        if is_cql {
            result.cql = Some(crepe_query::parse(expression)?);
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
    pub fn matches(&self, event: &PacketEvent) -> bool {
        self.cql.as_ref().is_none_or(|e| e.matches(event))
    }
    #[cfg(feature = "live")]
    pub fn ethernet_prefilter(&self) -> Option<String> {
        self.cql.as_ref().and_then(|e| e.ethernet_prefilter())
    }
}
