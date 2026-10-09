//! Shared typed event predicates for streaming policies and historical plans.
//! Missing fields use SQL's unknown value, including under negation.
use crepe_core::{Error, Result};
use serde_json::Value;
use std::net::IpAddr;
fn err(message: impl std::fmt::Display) -> Error {
    Error::new("CREPE-CQL-001", message)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    Text,
    Number,
    Port,
    Ip,
}
#[derive(Clone, Debug)]
pub struct Field {
    pub column: &'static str,
    pub kind: Type,
    family: Option<ipnet::IpNet>,
}
pub fn field(s: &str) -> Result<Field> {
    let column = match s {
        "event.id" | "event_id" => "event_id",
        "flow.id" | "flow_id" => "flow_id",
        "conversation.id" | "conversation_id" => "conversation_id",
        "identity.status" | "identity_status" => "identity_status",
        "sensor" => "sensor",
        "source" => "source",
        "timestamp" | "time" | "timestamp_ms" => "timestamp_ms",
        "timestamp_ns" => "timestamp_ns",
        "type" | "event.type" | "event_type" => "event_type",
        "src.ip" | "src_ip" | "ip.src" | "ipv6.src" => "src_ip",
        "dst.ip" | "dst_ip" | "ip.dst" | "ipv6.dst" => "dst_ip",
        "src.port" | "src_port" => "src_port",
        "dst.port" | "dst_port" => "dst_port",
        "proto" => "proto",
        "packets" | "flow.packets" => "packets",
        "bytes" | "flow.bytes" => "bytes",
        "window" | "window_start_ms" => "window_start_ms",
        "payload" => "payload",
        "dns.qname" | "dns_qname" => "dns_qname",
        "tls.server_name" | "tls_server_name" => "tls_server_name",
        "http.host" | "http_host" => "http_host",
        "http.method" | "http_method" => "http_method",
        "http.status" | "http_status" => "http_status",
        "file.sha256" | "file_sha256" => "file_sha256",
        "file.size" | "file_size" => "file_size",
        "anomaly.code" | "anomaly_code" => "anomaly_code",
        _ => return Err(err(format!("unknown field {s}"))),
    };
    let kind = match column {
        "src_ip" | "dst_ip" => Type::Ip,
        "src_port" | "dst_port" => Type::Port,
        "packets" | "bytes" | "timestamp_ms" | "window_start_ms" | "http_status" | "file_size" => {
            Type::Number
        }
        _ => Type::Text,
    };
    let family = if s.starts_with("ip.") {
        Some("0.0.0.0/0".parse().unwrap())
    } else if s.starts_with("ipv6.") {
        Some("::/0".parse().unwrap())
    } else {
        None
    };
    Ok(Field {
        column,
        kind,
        family,
    })
}
pub fn numeric(column: &str) -> bool {
    field(column).is_ok_and(|f| matches!(f.kind, Type::Number | Type::Port))
}
#[derive(Clone, Debug)]
pub enum Literal {
    Text(String),
    Number(i128),
    Ip(IpAddr),
}
#[derive(Clone, Copy, Debug)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
    Starts,
    Ends,
}
#[derive(Clone, Debug)]
pub enum Expr {
    All,
    Compare(Field, Op, Literal),
    Network(Field, ipnet::IpNet),
    Ports(Field, Vec<u16>),
    Not(Box<Self>),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
}
#[derive(Clone, Debug, PartialEq)]
enum Token {
    Word(String),
    Symbol(String),
}
fn lex(s: &str) -> Result<Vec<Token>> {
    if s.len() > 16384 {
        return Err(err("query length limit"));
    }
    let mut out = Vec::new();
    let mut it = s.char_indices().peekable();
    while let Some((at, c)) = it.next() {
        if c.is_whitespace() {
            continue;
        }
        let token = if c == '"' {
            let start = at;
            let mut escaped = false;
            let mut end = None;
            for (i, c) in it.by_ref() {
                if c == '"' && !escaped {
                    end = Some(i + 1);
                    break;
                }
                escaped = c == '\\' && !escaped;
            }
            let end = end.ok_or_else(|| err(format!("unterminated string at byte {start}")))?;
            Token::Word(s[start..end].into())
        } else if "()[],!<>=&|".contains(c) {
            let mut op = c.to_string();
            if it
                .peek()
                .is_some_and(|(_, n)| *n == '=' || (*n == c && matches!(c, '&' | '|')))
            {
                op.push(it.next().unwrap().1);
            }
            Token::Symbol(op)
        } else {
            let mut word = c.to_string();
            while it
                .peek()
                .is_some_and(|(_, c)| !c.is_whitespace() && !"()[],!<>=&|".contains(*c))
            {
                word.push(it.next().unwrap().1);
            }
            Token::Word(word)
        };
        out.push(token);
        if out.len() > 1024 {
            return Err(err("query token limit"));
        }
    }
    Ok(out)
}
struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}
impl Parser {
    fn take(&mut self, s: &str) -> bool {
        if self
            .tokens
            .get(self.pos)
            .is_some_and(|t| matches!(t,Token::Symbol(v)|Token::Word(v) if v==s))
        {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn word(&mut self) -> Result<String> {
        match self.tokens.get(self.pos) {
            Some(Token::Word(v)) => {
                self.pos += 1;
                Ok(v.clone())
            }
            _ => Err(err(format!(
                "expected field/literal at token {}",
                self.pos + 1
            ))),
        }
    }
    fn or(&mut self, d: usize) -> Result<Expr> {
        let mut x = self.and(d)?;
        while self.take("||") || self.take("or") {
            x = Expr::Or(Box::new(x), Box::new(self.and(d)?));
        }
        Ok(x)
    }
    fn and(&mut self, d: usize) -> Result<Expr> {
        let mut x = self.atom(d)?;
        while self.take("&&") || self.take("and") {
            x = Expr::And(Box::new(x), Box::new(self.atom(d)?));
        }
        Ok(x)
    }
    fn atom(&mut self, d: usize) -> Result<Expr> {
        if d > 32 {
            return Err(err("query nesting limit"));
        }
        if self.take("!") || self.take("not") {
            return Ok(Expr::Not(Box::new(self.atom(d + 1)?)));
        }
        if self.take("(") {
            let e = self.or(d + 1)?;
            if !self.take(")") {
                return Err(err("expected closing parenthesis"));
            }
            return Ok(e);
        }
        let f = field(&self.word()?)?;
        if self.take("in") {
            if f.kind == Type::Ip {
                return Ok(Expr::Network(
                    f,
                    self.word()?
                        .trim_matches('"')
                        .parse()
                        .map_err(|_| err("expected CIDR"))?,
                ));
            }
            if f.kind != Type::Port || !self.take("[") {
                return Err(err("in requires IP/CIDR or port/list"));
            }
            let mut ports = Vec::new();
            loop {
                ports.push(
                    self.word()?
                        .parse()
                        .map_err(|_| err("port must be 0..65535"))?,
                );
                if self.take("]") {
                    break;
                }
                if ports.len() >= 256 || !self.take(",") {
                    return Err(err("expected comma or closing bracket; at most 256 ports"));
                }
            }
            return Ok(Expr::Ports(f, ports));
        }
        let op = if self.take("==") {
            Op::Eq
        } else if self.take("!=") {
            Op::Ne
        } else if self.take("<=") {
            Op::Le
        } else if self.take(">=") {
            Op::Ge
        } else if self.take("<") {
            Op::Lt
        } else if self.take(">") {
            Op::Gt
        } else if self.take("contains") {
            Op::Contains
        } else if self.take("starts_with") {
            Op::Starts
        } else if self.take("ends_with") {
            Op::Ends
        } else {
            return Err(err("expected comparison operator"));
        };
        if matches!(op, Op::Contains | Op::Starts | Op::Ends) && f.kind != Type::Text {
            return Err(err("string operator requires text field"));
        }
        if matches!(op, Op::Lt | Op::Le | Op::Gt | Op::Ge)
            && !matches!(f.kind, Type::Number | Type::Port)
        {
            return Err(err("ordering requires numeric field"));
        }
        let mut word = self.word()?;
        if f.column == "timestamp_ms" && word == "now" {
            if !self.take("(") || !self.take(")") {
                return Err(err("expected now()"));
            }
            let mut time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(err)?
                .as_millis() as i128;
            if self.take("-") {
                time = time
                    .checked_sub(duration(&self.word()?)?)
                    .ok_or_else(|| err("duration overflow"))?;
            }
            word = time.to_string();
        }
        let value = match f.kind {
            Type::Text => Literal::Text(if word.starts_with('"') {
                serde_json::from_str::<String>(&word).map_err(err)?
            } else {
                word
            }),
            Type::Ip => Literal::Ip(
                word.trim_matches('"')
                    .parse()
                    .map_err(|_| err("expected IP address"))?,
            ),
            Type::Number | Type::Port => {
                let (digits, multiplier) = [
                    ("KB", 1024_i128),
                    ("MB", 1024_i128.pow(2)),
                    ("GB", 1024_i128.pow(3)),
                ]
                .into_iter()
                .find_map(|(s, n)| word.strip_suffix(s).map(|v| (v, n)))
                .unwrap_or((&word, 1));
                let n = digits
                    .parse::<i128>()
                    .ok()
                    .and_then(|n| n.checked_mul(multiplier))
                    .ok_or_else(|| err("expected bounded integer"))?;
                if f.kind == Type::Port && !(0..=65535).contains(&n) {
                    return Err(err("port must be 0..65535"));
                }
                Literal::Number(n)
            }
        };
        Ok(Expr::Compare(f, op, value))
    }
}
fn duration(s: &str) -> Result<i128> {
    let (n, scale) = [
        ("ms", 1_i128),
        ("s", 1000),
        ("m", 60000),
        ("h", 3600000),
        ("d", 86400000),
    ]
    .into_iter()
    .find_map(|(suffix, n)| s.strip_suffix(suffix).map(|v| (v, n)))
    .ok_or_else(|| err("invalid duration"))?;
    n.parse::<i128>()
        .ok()
        .filter(|n| *n >= 0)
        .and_then(|n| n.checked_mul(scale))
        .ok_or_else(|| err("duration overflow"))
}
pub fn parse(s: &str) -> Result<Expr> {
    if s.trim().is_empty() || s.trim() == "*" {
        return Ok(Expr::All);
    }
    let mut p = Parser {
        tokens: lex(s)?,
        pos: 0,
    };
    let e = p.or(0)?;
    if p.pos != p.tokens.len() {
        return Err(err("unexpected filter tokens"));
    }
    Ok(e)
}
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}
impl Expr {
    pub fn sql(&self) -> String {
        let qualify = |f: &Field, s: String| {
            f.family
                .map(|net| format!("(crepe_cidr({}, '{}') AND ({s}))", f.column, net))
                .unwrap_or(s)
        };
        match self {
            Self::All => "TRUE".into(),
            Self::And(a, b) => format!("({} AND {})", a.sql(), b.sql()),
            Self::Or(a, b) => format!("({} OR {})", a.sql(), b.sql()),
            Self::Not(e) => format!("NOT ({})", e.sql()),
            Self::Network(f, n) => qualify(f, format!("crepe_cidr({}, '{}')", f.column, n)),
            Self::Ports(f, p) => format!(
                "{} IN ({})",
                f.column,
                p.iter().map(u16::to_string).collect::<Vec<_>>().join(",")
            ),
            Self::Compare(f, op, v) => {
                let value = match v {
                    Literal::Text(s) => quote(s),
                    Literal::Ip(ip) => quote(&ip.to_string()),
                    Literal::Number(n) => n.to_string(),
                };
                let column = f.column;
                qualify(
                    f,
                    match op {
                        Op::Contains => format!("strpos({column}, {value}) > 0"),
                        Op::Starts => format!("starts_with({column}, {value})"),
                        Op::Ends => format!("ends_with({column}, {value})"),
                        _ => format!(
                            "{column} {} {value}",
                            match op {
                                Op::Eq => "=",
                                Op::Ne => "<>",
                                Op::Lt => "<",
                                Op::Le => "<=",
                                Op::Gt => ">",
                                Op::Ge => ">=",
                                _ => unreachable!(),
                            }
                        ),
                    },
                )
            }
        }
    }
    /// Packet execution shares typed fields and SQL-null semantics without building JSON.
    pub fn matches_packet(&self, p: &crepe_core::PacketEvent) -> bool {
        if let Self::Compare(field, op, Literal::Text(expected)) = self {
            if field.column == "proto" {
                let actual = match p.proto {
                    crepe_core::Protocol::Tcp => Some("tcp"),
                    crepe_core::Protocol::Udp => Some("udp"),
                    crepe_core::Protocol::Icmp => Some("icmp"),
                    crepe_core::Protocol::Icmpv6 => Some("icmpv6"),
                    _ => None,
                };
                if let Some(actual) = actual {
                    match op {
                        Op::Eq => return actual == expected,
                        Op::Ne => return actual != expected,
                        _ => {}
                    }
                }
            }
        }

        self.evaluate(&|f| {
            Some(match f.column {
                "src_ip" => Literal::Ip(p.src.ip),
                "dst_ip" => Literal::Ip(p.dst.ip),
                "src_port" => Literal::Number(i128::from(p.src.port?)),
                "dst_port" => Literal::Number(i128::from(p.dst.port?)),
                "proto" => Literal::Text(p.proto.to_string()),
                "event_type" => Literal::Text("packet".into()),
                "packets" => Literal::Number(1),
                "bytes" => Literal::Number(i128::from(p.header.original_len)),
                "timestamp_ms" => Literal::Number(
                    p.header
                        .timestamp_ns
                        .as_deref()?
                        .parse::<i128>()
                        .ok()?
                        .div_euclid(1_000_000),
                ),
                "timestamp_ns" => Literal::Text(p.header.timestamp_ns.clone()?),
                _ => return None,
            })
        }) == Some(true)
    }
    pub fn matches(&self, row: &Value) -> bool {
        self.evaluate(&|f| {
            let v = value(row, f.column)?;
            Some(match f.kind {
                Type::Ip => Literal::Ip(v.as_str()?.parse().ok()?),
                Type::Text => Literal::Text(v.as_str()?.into()),
                Type::Number | Type::Port => Literal::Number(
                    v.as_i64()
                        .map(i128::from)
                        .or_else(|| v.as_u64().map(i128::from))?,
                ),
            })
        }) == Some(true)
    }
    fn evaluate(&self, get: &impl Fn(&Field) -> Option<Literal>) -> Option<bool> {
        match self {
            Self::All => Some(true),
            Self::Not(e) => e.evaluate(get).map(|v| !v),
            Self::And(a, b) => match (a.evaluate(get), b.evaluate(get)) {
                (Some(false), _) | (_, Some(false)) => Some(false),
                (Some(true), Some(true)) => Some(true),
                _ => None,
            },
            Self::Or(a, b) => match (a.evaluate(get), b.evaluate(get)) {
                (Some(true), _) | (_, Some(true)) => Some(true),
                (Some(false), Some(false)) => Some(false),
                _ => None,
            },
            Self::Network(f, n) => {
                let Literal::Ip(ip) = get(f)? else {
                    return None;
                };
                Some(n.contains(&ip) && f.family.is_none_or(|net| net.contains(&ip)))
            }
            Self::Ports(f, ports) => {
                let Literal::Number(n) = get(f)? else {
                    return None;
                };
                Some(ports.contains(&u16::try_from(n).ok()?))
            }
            Self::Compare(f, op, literal) => {
                let actual = get(f)?;
                if let Some(net) = f.family {
                    let Literal::Ip(ip) = actual else {
                        return None;
                    };
                    if !net.contains(&ip) {
                        return Some(false);
                    }
                }
                let cmp = match (&actual, literal) {
                    (Literal::Number(a), Literal::Number(b)) => a.cmp(b),
                    (Literal::Ip(a), Literal::Ip(b)) => a.cmp(b),
                    (Literal::Text(a), Literal::Text(b)) => match op {
                        Op::Contains => return Some(a.contains(b)),
                        Op::Starts => return Some(a.starts_with(b)),
                        Op::Ends => return Some(a.ends_with(b)),
                        _ => a.cmp(b),
                    },
                    _ => return None,
                };
                Some(match op {
                    Op::Eq => cmp.is_eq(),
                    Op::Ne => !cmp.is_eq(),
                    Op::Lt => cmp.is_lt(),
                    Op::Le => !cmp.is_gt(),
                    Op::Gt => cmp.is_gt(),
                    Op::Ge => !cmp.is_lt(),
                    _ => false,
                })
            }
        }
    }
}

pub fn value(row: &Value, column: &str) -> Option<Value> {
    if let Some(v) = row.get(column).filter(|v| !v.is_null()) {
        return Some(v.clone());
    }
    let payload = row.get("payload")?;
    let parsed = payload
        .as_str()
        .and_then(|s| serde_json::from_str::<Value>(s).ok());
    let payload = parsed.as_ref().unwrap_or(payload);
    let pointer = match column {
        "dns_qname" => "/dns/questions/0/name",
        "tls_server_name" => "/protocol/server_name",
        "http_host" => "/protocol/host",
        "http_method" => "/protocol/method",
        "http_status" => "/protocol/status",
        "file_sha256" => "/protocol/sha256",
        "file_size" => "/protocol/size",
        "anomaly_code" => "/anomaly/code",
        _ => return None,
    };
    payload.pointer(pointer).filter(|v| !v.is_null()).cloned()
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn typed_shared_predicates() {
        let r = json!({"src_ip":"192.0.2.1","dst_port":443,"event_type":"dns.query","payload":{"dns":{"questions":[{"name":"bad.example"}]}}});
        for q in [
            "src.ip in 192.0.2.0/24 && dst.port in [80,443]",
            "dns.qname == \"bad.example\"",
            "type == dns.query",
        ] {
            assert!(parse(q).unwrap().matches(&r));
        }
        assert!(!parse("!(tls.server_name == x)").unwrap().matches(&r));
        for q in [
            "dst.port == 65536",
            "dst.port == \"443\"",
            "src.ip == nope",
            "bytes contains 4",
        ] {
            assert!(parse(q).is_err(), "{q}");
        }
    }
}
