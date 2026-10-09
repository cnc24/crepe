//! CQL: typed predicates with ! > && > || precedence and parentheses.
mod prefilter;
use crepe_core::{Error, PacketEvent, Protocol, Result};
use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Atom(String),
    Eq,
    Ne,
    In,
    And,
    Or,
    Not,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Src,
    Dst,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compare {
    Eq,
    Ne,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    Ip(Side, Compare, IpAddr),
    Port(Side, Compare, u16),
    Proto(Compare, Protocol),
    IpVersion(u8),
    Application(String),
    In(Side, IpNet),
    Ports(Side, Vec<u16>),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Predicate(Predicate),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}
fn err(message: impl std::fmt::Display) -> Error {
    Error::new("CREPE-CQL-001", message)
}

pub fn lex(input: &str) -> Result<Vec<Token>> {
    if input.len() > 4096 {
        return Err(err("query exceeds 4096 bytes"));
    }
    let mut tokens = Vec::new();
    let mut chars = input.char_indices().peekable();
    while let Some((offset, c)) = chars.next() {
        if c.is_whitespace() {
            continue;
        }
        let token = match c {
            '[' => Token::LBracket,
            ']' => Token::RBracket,
            ',' => Token::Comma,
            '(' => Token::LParen,
            ')' => Token::RParen,
            '!' if chars.peek().is_some_and(|(_, c)| *c == '=') => {
                chars.next();
                Token::Ne
            }
            '!' => Token::Not,
            '=' | '&' | '|' => {
                if chars.next().map(|(_, next)| next) != Some(c) {
                    return Err(err(format!("expected doubled operator at byte {offset}")));
                }
                match c {
                    '=' => Token::Eq,
                    '&' => Token::And,
                    _ => Token::Or,
                }
            }
            c if c.is_ascii_alphanumeric() || c == ':' => {
                let mut atom = String::from(c);
                while chars.peek().is_some_and(|(_, c)| {
                    c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '/' | '_')
                }) {
                    atom.push(chars.next().unwrap().1);
                }
                match atom.as_str() {
                    "in" => Token::In,
                    "and" => Token::And,
                    "or" => Token::Or,
                    "not" => Token::Not,
                    _ => Token::Atom(atom),
                }
            }
            _ => return Err(err(format!("unexpected character at byte {offset}"))),
        };
        tokens.push(token);
        if tokens.len() > 256 {
            return Err(err("query exceeds 256 tokens"));
        }
    }
    Ok(tokens)
}
pub fn parse(input: &str) -> Result<Expr> {
    let tokens = lex(input)?;
    let mut parser = Parser {
        tokens: &tokens,
        pos: 0,
    };
    let result = parser.or(0)?;
    if parser.pos != tokens.len() {
        return Err(err(format!("unexpected token {}", parser.pos + 1)));
    }
    Ok(result)
}
struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
}
impl Parser<'_> {
    fn take(&mut self, token: &Token) -> bool {
        if self.tokens.get(self.pos) == Some(token) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn atom(&mut self) -> Result<String> {
        if let Some(Token::Atom(s)) = self.tokens.get(self.pos) {
            self.pos += 1;
            Ok(s.clone())
        } else {
            Err(err(format!(
                "expected field or value at token {}",
                self.pos + 1
            )))
        }
    }
    fn or(&mut self, depth: usize) -> Result<Expr> {
        let mut lhs = self.and(depth)?;
        while self.take(&Token::Or) {
            lhs = Expr::Or(Box::new(lhs), Box::new(self.and(depth)?));
        }
        Ok(lhs)
    }
    fn and(&mut self, depth: usize) -> Result<Expr> {
        let mut lhs = self.unary(depth)?;
        while self.take(&Token::And) {
            lhs = Expr::And(Box::new(lhs), Box::new(self.unary(depth)?));
        }
        Ok(lhs)
    }
    fn unary(&mut self, depth: usize) -> Result<Expr> {
        if depth > 32 {
            return Err(err("query nesting exceeds 32 levels"));
        }
        if self.take(&Token::Not) {
            return Ok(Expr::Not(Box::new(self.unary(depth + 1)?)));
        }
        if self.take(&Token::LParen) {
            let e = self.or(depth + 1)?;
            if !self.take(&Token::RParen) {
                return Err(err("missing closing parenthesis"));
            }
            return Ok(e);
        }
        let original = self.atom()?;
        let bare = match original.as_str() {
            "tcp" => Some(Predicate::Proto(Compare::Eq, Protocol::Tcp)),
            "udp" => Some(Predicate::Proto(Compare::Eq, Protocol::Udp)),
            "icmp" => Some(Predicate::Proto(Compare::Eq, Protocol::Icmp)),
            "icmpv6" => Some(Predicate::Proto(Compare::Eq, Protocol::Icmpv6)),
            "ip" => Some(Predicate::IpVersion(4)),
            "ipv6" => Some(Predicate::IpVersion(6)),
            "http" | "dns" | "tls" | "ssh" => Some(Predicate::Application(original.clone())),
            _ => None,
        };
        if let Some(predicate) = bare {
            return Ok(Expr::Predicate(predicate));
        }
        let (field, guard, both) = match original.as_str() {
            "ip.src" => ("src.ip", Some(Predicate::IpVersion(4)), false),
            "ip.dst" => ("dst.ip", Some(Predicate::IpVersion(4)), false),
            "ipv6.src" => ("src.ip", Some(Predicate::IpVersion(6)), false),
            "ipv6.dst" => ("dst.ip", Some(Predicate::IpVersion(6)), false),
            "ip.addr" => ("src.ip", Some(Predicate::IpVersion(4)), true),
            "ipv6.addr" => ("src.ip", Some(Predicate::IpVersion(6)), true),
            "tcp.srcport" => (
                "src.port",
                Some(Predicate::Proto(Compare::Eq, Protocol::Tcp)),
                false,
            ),
            "tcp.dstport" => (
                "dst.port",
                Some(Predicate::Proto(Compare::Eq, Protocol::Tcp)),
                false,
            ),
            "udp.srcport" => (
                "src.port",
                Some(Predicate::Proto(Compare::Eq, Protocol::Udp)),
                false,
            ),
            "udp.dstport" => (
                "dst.port",
                Some(Predicate::Proto(Compare::Eq, Protocol::Udp)),
                false,
            ),
            "tcp.port" => (
                "src.port",
                Some(Predicate::Proto(Compare::Eq, Protocol::Tcp)),
                true,
            ),
            "udp.port" => (
                "src.port",
                Some(Predicate::Proto(Compare::Eq, Protocol::Udp)),
                true,
            ),
            other => (other, None, false),
        };
        let field = field.to_string();
        let qualify = |predicate: Predicate| {
            let second = if both {
                match &predicate {
                    Predicate::Ip(_, op, v) => Some(Predicate::Ip(Side::Dst, *op, *v)),
                    Predicate::Port(_, op, v) => Some(Predicate::Port(Side::Dst, *op, *v)),
                    Predicate::In(_, v) => Some(Predicate::In(Side::Dst, *v)),
                    Predicate::Ports(_, v) => Some(Predicate::Ports(Side::Dst, v.clone())),
                    _ => None,
                }
            } else {
                None
            };
            let all = matches!(
                predicate,
                Predicate::Ip(_, Compare::Ne, _) | Predicate::Port(_, Compare::Ne, _)
            );
            let mut result = Expr::Predicate(predicate);
            if let Some(other) = second {
                result = if all {
                    Expr::And(Box::new(result), Box::new(Expr::Predicate(other)))
                } else {
                    Expr::Or(Box::new(result), Box::new(Expr::Predicate(other)))
                };
            }
            if let Some(guard) = guard.clone() {
                result = Expr::And(Box::new(Expr::Predicate(guard)), Box::new(result));
            }
            result
        };
        let side = match field.as_str() {
            "src.ip" | "src.port" => Some(Side::Src),
            "dst.ip" | "dst.port" => Some(Side::Dst),
            "proto" => None,
            _ => return Err(err(format!("unknown field {field}"))),
        };
        if self.take(&Token::In) {
            if field.ends_with(".port") {
                if !self.take(&Token::LBracket) {
                    return Err(err("expected port list [80, 443]"));
                }
                let mut ports = Vec::new();
                loop {
                    ports.push(
                        self.atom()?
                            .parse::<u16>()
                            .map_err(|_| err("expected port 0..65535"))?,
                    );
                    if self.take(&Token::RBracket) {
                        break;
                    }
                    if !self.take(&Token::Comma) {
                        return Err(err("expected comma or closing bracket"));
                    }
                }
                ports.sort_unstable();
                ports.dedup();
                return Ok(qualify(Predicate::Ports(side.unwrap(), ports)));
            }
            if !field.ends_with(".ip") {
                return Err(err("in requires an IP field"));
            }
            let value = self
                .atom()?
                .parse::<IpNet>()
                .map_err(|_| err("expected IPv4/IPv6 CIDR"))?;
            return Ok(qualify(Predicate::In(side.unwrap(), value)));
        }
        let op = if self.take(&Token::Eq) {
            Compare::Eq
        } else if self.take(&Token::Ne) {
            Compare::Ne
        } else {
            return Err(err("expected ==, != or in"));
        };
        let value = self.atom()?;
        let predicate = match field.as_str() {
            "src.ip" | "dst.ip" => Predicate::Ip(
                side.unwrap(),
                op,
                value
                    .parse()
                    .map_err(|_| err("expected IPv4/IPv6 address"))?,
            ),
            "src.port" | "dst.port" => Predicate::Port(
                side.unwrap(),
                op,
                value.parse().map_err(|_| err("expected port 0..65535"))?,
            ),
            _ => Predicate::Proto(
                op,
                match value.to_ascii_lowercase().as_str() {
                    "tcp" => Protocol::Tcp,
                    "udp" => Protocol::Udp,
                    "icmp" => Protocol::Icmp,
                    "icmpv6" => Protocol::Icmpv6,
                    _ => Protocol::from_number(value.parse().map_err(|_| {
                        err("expected tcp, udp, icmp, icmpv6 or IP protocol number 0..255")
                    })?),
                },
            ),
        };
        Ok(qualify(predicate))
    }
}
impl Expr {
    pub fn matches(&self, event: &PacketEvent) -> bool {
        self.matches_application(event, None)
    }
    pub fn matches_application(&self, event: &PacketEvent, application: Option<&str>) -> bool {
        match self {
            Self::Not(e) => !e.matches_application(event, application),
            Self::And(a, b) => {
                a.matches_application(event, application)
                    && b.matches_application(event, application)
            }
            Self::Or(a, b) => {
                a.matches_application(event, application)
                    || b.matches_application(event, application)
            }
            Self::Predicate(p) => {
                let endpoint = |side: &Side| match side {
                    Side::Src => &event.src,
                    Side::Dst => &event.dst,
                };
                let compare = |op: &Compare, equal: bool| match op {
                    Compare::Eq => equal,
                    Compare::Ne => !equal,
                };
                match p {
                    Predicate::Ip(side, op, ip) => compare(op, endpoint(side).ip == *ip),
                    Predicate::Port(side, op, port) => {
                        endpoint(side).port.is_some_and(|p| compare(op, p == *port))
                    }
                    Predicate::IpVersion(version) => event.src.ip.is_ipv4() == (*version == 4),
                    Predicate::Application(name) => application == Some(name.as_str()),
                    Predicate::Proto(op, proto) => compare(op, event.proto == *proto),
                    Predicate::In(side, net) => net.contains(&endpoint(side).ip),
                    Predicate::Ports(side, ports) => endpoint(side)
                        .port
                        .is_some_and(|p| ports.binary_search(&p).is_ok()),
                }
            }
        }
    }
}

impl Expr {
    /// Whether evaluation needs packet-local application recognition.
    pub fn needs_application(&self) -> bool {
        match self {
            Self::Predicate(Predicate::Application(_)) => true,
            Self::Predicate(_) => false,
            Self::Not(e) => e.needs_application(),
            Self::And(a, b) | Self::Or(a, b) => a.needs_application() || b.needs_application(),
        }
    }
}

#[cfg(test)]
mod application_requirement_tests {
    #[test]
    fn application_work_is_only_required_by_application_predicates() {
        for expression in [
            "dst.port == 443",
            "!(tcp.port == 80) && ip.src == 192.0.2.10",
            "proto == udp",
        ] {
            assert!(!super::parse(expression).unwrap().needs_application());
        }
        for expression in ["http", "!(dns || tls)", "dst.port == 443 && (http || ssh)"] {
            assert!(super::parse(expression).unwrap().needs_application());
        }
    }
}

pub mod event;
