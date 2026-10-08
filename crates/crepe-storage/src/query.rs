//! Small, deliberately closed CQL pipeline grammar. No arbitrary SQL reaches DataFusion.
use crepe_core::{Error, Result};
fn err(m: &str) -> Error {
    Error::new("CREPE-CQL-001", m)
}
fn field(s: &str) -> Result<&'static str> {
    match s {
        "event.id" | "event_id" => Ok("event_id"),
        "flow.id" | "flow_id" => Ok("flow_id"),
        "conversation.id" | "conversation_id" => Ok("conversation_id"),
        "identity.status" | "identity_status" => Ok("identity_status"),
        "sensor" => Ok("sensor"),
        "source" => Ok("source"),
        "time" | "timestamp" | "timestamp_ms" => Ok("timestamp_ms"),
        "timestamp_ns" => Ok("timestamp_ns"),
        "type" | "event.type" | "event_type" => Ok("event_type"),
        "src.ip" | "src_ip" | "ip.src" | "ipv6.src" => Ok("src_ip"),
        "dst.ip" | "dst_ip" | "ip.dst" | "ipv6.dst" => Ok("dst_ip"),
        "src.port" | "src_port" => Ok("src_port"),
        "dst.port" | "dst_port" => Ok("dst_port"),
        "proto" => Ok("proto"),
        "packets" | "flow.packets" => Ok("packets"),
        "bytes" | "flow.bytes" => Ok("bytes"),
        "window" | "window_start_ms" => Ok("window_start_ms"),
        "payload" => Ok("payload"),
        "tls.server_name" | "tls_server_name" => Ok("tls_server_name"),
        "dns.qname" | "dns_qname" => Ok("dns_qname"),
        "http.host" | "http_host" => Ok("http_host"),
        "http.method" | "http_method" => Ok("http_method"),
        "http.status" | "http_status" => Ok("http_status"),
        "file.sha256" | "file_sha256" => Ok("file_sha256"),
        "file.size" | "file_size" => Ok("file_size"),
        "anomaly.code" | "anomaly_code" => Ok("anomaly_code"),
        _ => Err(err("unknown historical field")),
    }
}
fn numeric(s: &str) -> bool {
    matches!(
        s,
        "src_port"
            | "dst_port"
            | "packets"
            | "bytes"
            | "timestamp_ms"
            | "window_start_ms"
            | "http_status"
            | "file_size"
    )
}
fn literal(s: &str, num: bool) -> Result<String> {
    if num {
        let (digits, multiplier) = [
            ("KB", 1024_i128),
            ("MB", 1024_i128.pow(2)),
            ("GB", 1024_i128.pow(3)),
        ]
        .into_iter()
        .find_map(|(suffix, scale)| s.strip_suffix(suffix).map(|n| (n, scale)))
        .unwrap_or((s, 1));
        let number = digits
            .parse::<i128>()
            .map_err(|_| err("expected integer or KB/MB/GB size"))?;
        Ok(number
            .checked_mul(multiplier)
            .ok_or_else(|| err("numeric literal overflow"))?
            .to_string())
    } else {
        let s = s
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(s);
        if s.len() > 1024 || s.contains(['\n', '\r', '\0']) {
            return Err(err("invalid string literal"));
        }
        Ok(format!("'{}'", s.replace('\'', "''")))
    }
}
#[derive(Clone, Debug)]
enum Token {
    Word(String),
    Op(String),
    Left,
    Right,
    Not,
    And,
    Or,
}
fn lex(s: &str) -> Result<Vec<Token>> {
    let mut out = vec![];
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c.is_whitespace() {
            continue;
        }
        out.push(match c {
            '(' => Token::Left,
            ')' => Token::Right,
            '!' if it.peek() != Some(&'=') => Token::Not,
            '&' | '|' => {
                if it.next() != Some(c) {
                    return Err(err("expected && or ||"));
                }
                if c == '&' {
                    Token::And
                } else {
                    Token::Or
                }
            }
            '=' | '!' | '<' | '>' => {
                let mut op = c.to_string();
                if it.peek() == Some(&'=') {
                    op.push(it.next().unwrap());
                }
                if op == "=" || op == "!" {
                    return Err(err("invalid comparison"));
                }
                Token::Op(op)
            }
            '"' => {
                let mut v = String::from("\"");
                let mut closed = false;
                for c in it.by_ref() {
                    v.push(c);
                    if c == '"' {
                        closed = true;
                        break;
                    }
                }
                if !closed {
                    return Err(err("unterminated string"));
                }
                Token::Word(v)
            }
            _ => {
                let mut v = c.to_string();
                while it
                    .peek()
                    .is_some_and(|c| !c.is_whitespace() && !"()!<>=&|".contains(*c))
                {
                    v.push(it.next().unwrap());
                }
                Token::Word(v)
            }
        });
        if out.len() > 1024 {
            return Err(err("query token limit"));
        }
    }
    Ok(out)
}
struct Parser {
    tokens: Vec<Token>,
    p: usize,
}
impl Parser {
    fn expr(&mut self, depth: usize) -> Result<String> {
        if depth > 32 {
            return Err(err("query nesting limit"));
        }
        let mut s = self.and(depth + 1)?;
        while matches!(self.tokens.get(self.p), Some(Token::Or)) {
            self.p += 1;
            s = format!("({s} OR {})", self.and(depth + 1)?);
        }
        Ok(s)
    }
    fn and(&mut self, d: usize) -> Result<String> {
        let mut s = self.atom(d)?;
        while matches!(self.tokens.get(self.p), Some(Token::And)) {
            self.p += 1;
            s = format!("({s} AND {})", self.atom(d)?);
        }
        Ok(s)
    }
    fn atom(&mut self, d: usize) -> Result<String> {
        if d > 32 {
            return Err(err("query nesting limit"));
        }
        if matches!(self.tokens.get(self.p), Some(Token::Not)) {
            self.p += 1;
            return Ok(format!("NOT ({})", self.atom(d + 1)?));
        }
        if matches!(self.tokens.get(self.p), Some(Token::Left)) {
            self.p += 1;
            let s = self.expr(d + 1)?;
            if !matches!(self.tokens.get(self.p), Some(Token::Right)) {
                return Err(err("expected closing parenthesis"));
            }
            self.p += 1;
            return Ok(format!("({s})"));
        }
        let Some(Token::Word(f)) = self.tokens.get(self.p) else {
            return Err(err("expected field"));
        };
        let family = if f.starts_with("ip.") {
            Some("0.0.0.0/0")
        } else if f.starts_with("ipv6.") {
            Some("::/0")
        } else {
            None
        };
        let f = field(f)?;
        let qualify = |expression: String| {
            family
                .map(|net| format!("(crepe_cidr({f}, '{net}') AND ({expression}))"))
                .unwrap_or(expression)
        };
        if let Some(Token::Word(operator)) = self.tokens.get(self.p + 1) {
            let Some(Token::Word(value)) = self.tokens.get(self.p + 2) else {
                return Err(err("expected value"));
            };
            if operator == "in" && matches!(f, "src_port" | "dst_port") {
                let mut list = String::new();
                let mut consumed = 0;
                for token in &self.tokens[self.p + 2..] {
                    let Token::Word(word) = token else {
                        break;
                    };
                    list.push_str(word);
                    consumed += 1;
                    if word.ends_with(']') {
                        break;
                    }
                }
                let body = list
                    .strip_prefix('[')
                    .and_then(|s| s.strip_suffix(']'))
                    .ok_or_else(|| err("expected port list"))?;
                let ports = body
                    .split(',')
                    .map(|s| s.parse::<u16>().map_err(|_| err("invalid port")))
                    .collect::<Result<Vec<_>>>()?;
                if ports.len() > 256 {
                    return Err(err("port list limit"));
                }
                self.p += 2 + consumed;
                return Ok(format!(
                    "{f} IN ({})",
                    ports
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                ));
            }
            let expression = match operator.as_str() {
                "in" if matches!(f, "src_ip" | "dst_ip") => {
                    let net = value
                        .trim_matches('"')
                        .parse::<ipnet::IpNet>()
                        .map_err(|_| err("expected CIDR"))?;
                    format!("crepe_cidr({f}, '{}')", net)
                }
                "ends_with" | "starts_with" | "contains" if !numeric(f) => {
                    let value = literal(value, false)?;
                    if operator == "contains" {
                        format!("strpos({f}, {value}) > 0")
                    } else {
                        format!("{operator}({f}, {value})")
                    }
                }
                _ => return Err(err("unsupported field/operator combination")),
            };
            self.p += 3;
            return Ok(qualify(expression));
        }
        let Some(Token::Op(op)) = self.tokens.get(self.p + 1) else {
            return Err(err("expected comparison"));
        };
        let op = match op.as_str() {
            "==" => "=",
            "!=" => "<>",
            "<" => "<",
            ">" => ">",
            "<=" => "<=",
            ">=" => ">=",
            _ => return Err(err("invalid operator")),
        };
        if !numeric(f) && !matches!(op, "=" | "<>") {
            return Err(err("ordering requires numeric field"));
        }
        let Some(Token::Word(v)) = self.tokens.get(self.p + 2) else {
            return Err(err("expected value"));
        };
        if f == "timestamp_ms" && v == "now" {
            if !matches!(self.tokens.get(self.p + 3), Some(Token::Left))
                || !matches!(self.tokens.get(self.p + 4), Some(Token::Right))
            {
                return Err(err("expected now()"));
            }
            let mut milliseconds = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| err("clock before epoch"))?
                .as_millis() as i128;
            self.p += 5;
            if matches!(self.tokens.get(self.p), Some(Token::Word(sign)) if sign == "-") {
                let Some(Token::Word(duration)) = self.tokens.get(self.p + 1) else {
                    return Err(err("expected duration"));
                };
                let (number, scale) = [
                    ("ms", 1),
                    ("s", 1000),
                    ("m", 60000),
                    ("h", 3600000),
                    ("d", 86400000),
                ]
                .into_iter()
                .find_map(|(suffix, scale)| {
                    duration.strip_suffix(suffix).map(|number| (number, scale))
                })
                .ok_or_else(|| err("invalid duration unit"))?;
                let delta = number
                    .parse::<i128>()
                    .ok()
                    .filter(|n| *n >= 0)
                    .and_then(|n| n.checked_mul(scale))
                    .ok_or_else(|| err("invalid duration"))?;
                milliseconds = milliseconds
                    .checked_sub(delta)
                    .ok_or_else(|| err("duration overflow"))?;
                self.p += 2;
            }
            return Ok(format!("{f} {op} {milliseconds}"));
        }
        let v = literal(v, numeric(f))?;
        self.p += 3;
        Ok(qualify(format!("{f} {op} {v}")))
    }
}
pub fn compile(cql: &str) -> Result<String> {
    if cql.len() > 16384 {
        return Err(err("query length limit"));
    }
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let b = cql.as_bytes();
    for i in 0..b.len() {
        if b[i] == b'"' {
            quoted = !quoted
        }
        if b[i] == b'|'
            && !quoted
            && b.get(i.wrapping_sub(1)) != Some(&b'|')
            && b.get(i + 1) != Some(&b'|')
        {
            parts.push(cql[start..i].trim());
            start = i + 1;
        }
    }
    parts.push(cql[start..].trim());
    if parts.len() > 8 {
        return Err(err("pipeline stage limit"));
    }
    let first = parts.remove(0);
    let filter = first.strip_prefix("where ").unwrap_or(first);
    let mut projection = vec!["*".to_string()];
    for (name, alias, pointer, numeric) in [
        (
            "tls.server_name",
            "tls_server_name",
            "/protocol/server_name",
            false,
        ),
        ("dns.qname", "dns_qname", "/dns/questions/0/name", false),
        ("http.host", "http_host", "/protocol/host", false),
        ("http.method", "http_method", "/protocol/method", false),
        ("http.status", "http_status", "/protocol/status", true),
        ("file.sha256", "file_sha256", "/protocol/sha256", false),
        ("file.size", "file_size", "/protocol/size", true),
        ("anomaly.code", "anomaly_code", "/anomaly/code", false),
    ] {
        if cql.contains(name) || cql.contains(alias) {
            let expression = format!("crepe_json(payload, '{pointer}')");
            let expression = if numeric {
                format!("TRY_CAST({expression} AS BIGINT)")
            } else {
                expression
            };
            projection.push(format!("{expression} AS {alias}"));
        }
    }
    let mut sql = format!(
        "SELECT * FROM (SELECT {} FROM events)",
        projection.join(",")
    );
    if !filter.trim().is_empty() && filter.trim() != "*" {
        let mut p = Parser {
            tokens: lex(filter.trim())?,
            p: 0,
        };
        let predicate = p.expr(0)?;
        if p.p != p.tokens.len() {
            return Err(err("unexpected filter tokens"));
        }
        sql.push_str(&format!(" WHERE {predicate}"));
    }
    let mut aggregate = false;
    let mut pending_group: Option<String> = None;
    let mut window = false;
    let mut aliases = std::collections::BTreeSet::<String>::new();
    for (index, part) in parts.iter().enumerate() {
        let words: Vec<_> = part.split_whitespace().collect();
        match words.as_slice() {
            ["select", rest @ ..] if !rest.is_empty() => {
                let names = rest.join("");
                let fields = names.split(',').map(field).collect::<Result<Vec<_>>>()?;
                sql = format!("SELECT {} FROM ({sql})", fields.join(","));
            }
            ["group", rest @ ..] if !rest.is_empty() => {
                let names = rest.join("");
                let fields = names.split(',').map(field).collect::<Result<Vec<_>>>()?;
                let mut fields = fields.join(",");
                if window && !fields.split(',').any(|s| s == "window_start_ms") {
                    fields = format!("window_start_ms,{fields}");
                }
                let next_aggregate = parts
                    .get(index + 1)
                    .and_then(|part| part.split_whitespace().next())
                    .is_some_and(|word| ["sum", "avg", "min", "max", "count"].contains(&word));
                if next_aggregate {
                    pending_group = Some(fields);
                } else {
                    sql=format!("SELECT {fields}, COUNT(*) AS count, SUM(packets) AS packets, SUM(bytes) AS bytes FROM ({sql}) GROUP BY {fields}");
                }
                aggregate = true;
            }
            [function @ ("sum" | "avg" | "min" | "max"), column, "as", alias] => {
                let column = field(column)?;
                if !numeric(column)
                    || alias.is_empty()
                    || alias.len() > 32
                    || !alias.as_bytes()[0].is_ascii_alphabetic()
                    || !alias
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                {
                    return Err(err("numeric aggregate and simple alias required"));
                }
                let group = pending_group.take();
                let prefix = group.as_ref().map(|g| format!("{g}, ")).unwrap_or_default();
                let suffix = group
                    .as_ref()
                    .map(|g| format!(" GROUP BY {g}"))
                    .unwrap_or_default();
                sql = format!(
                    "SELECT {prefix}{function}({column}) AS \"{alias}\" FROM ({sql}){suffix}"
                );
                aliases.insert(alias.to_string());
                aggregate = true;
            }
            ["distinct", column] => {
                let column = field(column)?;
                sql = format!("SELECT DISTINCT {column} FROM ({sql})");
            }
            ["window", duration] => {
                if window || aggregate {
                    return Err(err("window must precede aggregation and occur once"));
                }
                let (n, scale) = [("s", 1000_i64), ("m", 60000), ("h", 3600000)]
                    .into_iter()
                    .find_map(|(suffix, scale)| duration.strip_suffix(suffix).map(|n| (n, scale)))
                    .ok_or_else(|| err("window requires s, m or h"))?;
                let width = n
                    .parse::<i64>()
                    .ok()
                    .and_then(|n| n.checked_mul(scale))
                    .filter(|n| (1000..=86400000).contains(n))
                    .ok_or_else(|| err("window must be 1 second to 24 hours"))?;
                sql = format!("SELECT *, CAST(FLOOR(CAST(timestamp_ms AS DOUBLE) / {width}) AS BIGINT) * {width} AS window_start_ms FROM ({sql})");
                window = true;
                pending_group = Some("window_start_ms".into());
            }
            ["top", limit, column] => {
                let limit = limit
                    .parse::<usize>()
                    .ok()
                    .filter(|n| (1..=10000).contains(n))
                    .ok_or_else(|| err("invalid top limit"))?;
                let column = field(column)?;
                sql = format!("SELECT {column}, COUNT(*) AS count FROM ({sql}) GROUP BY {column} ORDER BY count DESC LIMIT {limit}");
                aggregate = true;
            }
            ["timeline"] => {
                sql = format!("SELECT * FROM ({sql}) ORDER BY timestamp_ms ASC NULLS LAST");
            }
            ["count"] => {
                if let Some(group) = pending_group.take() {
                    sql =
                        format!("SELECT {group}, COUNT(*) AS count FROM ({sql}) GROUP BY {group}");
                } else {
                    sql = format!("SELECT COUNT(*) AS count FROM ({sql})");
                }
                aggregate = true;
            }
            ["sort", f] | ["sort", f, "asc"] | ["sort", f, "desc"] => {
                let f = if aliases.contains(*f) || (*f == "count" && aggregate) {
                    *f
                } else {
                    field(f)?
                };
                let dir = if words.last() == Some(&"desc") {
                    "DESC"
                } else {
                    "ASC"
                };
                sql = format!("SELECT * FROM ({sql}) ORDER BY \"{f}\" {dir} NULLS LAST");
            }
            ["limit", n] => {
                let n = n.parse::<usize>().map_err(|_| err("invalid limit"))?;
                if n == 0 || n > 10000 {
                    return Err(err("limit must be 1..10000"));
                }
                sql = format!("SELECT * FROM ({sql}) LIMIT {n}");
            }
            _ => return Err(err("expected select, group, count, sort or limit stage")),
        }
    }
    Ok(format!("SELECT * FROM ({sql}) LIMIT 10000"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pipelines_and_injection() {
        assert!(compile("dst.port == 443 && (proto == tcp || proto == udp) | group src.ip | sort bytes desc | limit 20").unwrap().contains("GROUP BY src_ip"));
        assert!(compile("payload == \"x'; DROP TABLE events; --\" | count")
            .unwrap()
            .contains("x''; DROP"));
        assert!(compile("x == 1").is_err());
        assert!(compile("bytes > nope").is_err());
        assert!(compile("* | limit 10001").is_err());
    }
}
