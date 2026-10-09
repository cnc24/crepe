//! Historical pipeline planning over the shared typed event predicate AST.
use crepe_core::{Error, Result};
fn err(m: &str) -> Error {
    Error::new("CREPE-CQL-001", m)
}
fn field(s: &str) -> Result<&'static str> {
    Ok(crepe_query::event::field(s)?.column)
}
fn numeric(s: &str) -> bool {
    crepe_query::event::numeric(s)
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
        if b[i] == b'"'
            && b[..i]
                .iter()
                .rev()
                .take_while(|c| **c == b'\\')
                .count()
                .is_multiple_of(2)
        {
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
        let predicate = crepe_query::event::parse(filter.trim())?.sql();
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
