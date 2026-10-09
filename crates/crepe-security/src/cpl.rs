//! CPL v1: bounded, declarative reactions. No loops, IO, execution or network actions.
use crepe_core::{Error, Result};
use crepe_query::event::{self, Expr};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
fn err(e: impl std::fmt::Display) -> Error {
    Error::new("CREPE-CPL-001", e)
}
#[derive(Clone, Debug)]
struct Rule {
    id: String,
    version: String,
    event: String,
    predicate: Expr,
    actions: Vec<Action>,
}
#[derive(Clone, Debug)]
enum Action {
    Notice { severity: String, message: String },
    Tag { name: String, value: String },
    Metric { name: String, value: u64 },
    Log { level: String, message: String },
}
#[derive(Serialize)]
pub struct Effect {
    pub event_type: &'static str,
    pub rule_id: String,
    pub rule_version: String,
    pub program_version: String,
    pub data: Value,
}
pub struct Program {
    rules: Vec<Rule>,
    version: String,
    counters: BTreeMap<String, u64>,
    dedup: BTreeMap<String, std::time::Instant>,
    window: std::time::Instant,
    notices: u64,
    pub suppressed: u64,
}
fn split(s: &str, delimiter: char) -> Result<Vec<&str>> {
    let mut out = Vec::new();
    let (mut quote, mut escaped, mut start) = (false, false, 0);
    for (i, c) in s.char_indices() {
        if c == '"' && !escaped {
            quote = !quote;
        }
        if !quote && c == delimiter {
            out.push(s[start..i].trim());
            start = i + c.len_utf8();
        }
        escaped = c == '\\' && !escaped;
    }
    if quote {
        return Err(err("unterminated string"));
    }
    out.push(s[start..].trim());
    Ok(out)
}
fn text(s: &str) -> Result<String> {
    let value = if s.starts_with('"') {
        serde_json::from_str::<String>(s).map_err(err)?
    } else {
        s.to_string()
    };
    if value.len() > 512 || value.contains(['\n', '\r', '\0']) {
        return Err(err("action text must be a single line, at most 512 bytes"));
    }
    Ok(value)
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}
impl Program {
    pub fn parse(source: &str) -> Result<Self> {
        if source.len() > 65536 {
            return Err(err("CPL source exceeds 64 KiB"));
        }
        let version = blake3::hash(source.as_bytes()).to_hex().to_string();
        let mut rules = Vec::new();
        let mut rest = source.trim();
        let mut ids = BTreeSet::new();
        let mut metrics = BTreeSet::new();
        while !rest.is_empty() {
            if rules.len() >= 256 {
                return Err(err("at most 256 CPL rules"));
            }
            let mut quoted = false;
            let mut escaped = false;
            let mut open = None;
            for (i, c) in rest.char_indices() {
                if c == '"' && !escaped {
                    quoted = !quoted;
                }
                if c == '{' && !quoted {
                    open = Some(i);
                    break;
                }
                escaped = c == '\\' && !escaped;
            }
            let open = open.ok_or_else(|| err("expected rule body { ... }"))?;
            let header = rest[..open].trim();
            let at = header
                .match_indices("where")
                .find(|(i, _)| {
                    *i > 0
                        && header.as_bytes()[i - 1].is_ascii_whitespace()
                        && header
                            .as_bytes()
                            .get(i + 5)
                            .is_some_and(u8::is_ascii_whitespace)
                })
                .map(|(i, _)| i)
                .ok_or_else(|| err("expected on EVENT where PREDICATE"))?;
            let (selector, predicate) = (&header[..at], header[at + 5..].trim());
            let words: Vec<_> = selector.split_whitespace().collect();
            let (id, rule_version, event) = match words.as_slice() {
                ["on", event] => (format!("rule-{}", rules.len() + 1), version.clone(), *event),
                ["rule", id, "version", v, "on", event] if identifier(id) => {
                    (id.to_string(), text(v)?, *event)
                }
                _ => return Err(err("expected [rule ID version VERSION] on EVENT where ...")),
            };
            if !identifier(event) && event != "*" {
                return Err(err("invalid event selector"));
            }
            if !ids.insert(id.clone()) {
                return Err(err("duplicate rule ID"));
            }
            let mut close = None;
            quoted = false;
            escaped = false;
            for (i, c) in rest[open + 1..].char_indices() {
                if c == '"' && !escaped {
                    quoted = !quoted;
                }
                if c == '}' && !quoted {
                    close = Some(open + 1 + i);
                    break;
                }
                if c == '{' && !quoted {
                    return Err(err("nested actions are not supported"));
                }
                escaped = c == '\\' && !escaped;
            }
            let close = close.ok_or_else(|| err("unterminated rule body"))?;
            let mut actions = Vec::new();
            for statement in split(&rest[open + 1..close], ';')?
                .into_iter()
                .filter(|s| !s.is_empty())
            {
                if actions.len() >= 8 {
                    return Err(err("at most eight actions per rule"));
                }
                let (kind, args) = statement
                    .split_once('(')
                    .ok_or_else(|| err("expected action(arguments)"))?;
                let args = args
                    .strip_suffix(')')
                    .ok_or_else(|| err("expected closing action parenthesis"))?;
                if kind.trim() == "tag" && args.trim().starts_with('"') {
                    actions.push(Action::Tag {
                        name: text(args.trim())?,
                        value: "true".into(),
                    });
                    continue;
                }
                let mut fields = BTreeMap::new();
                for arg in split(args, ',')? {
                    let (k, v) = arg
                        .split_once(':')
                        .ok_or_else(|| err("expected named argument: value"))?;
                    if fields.insert(k.trim(), v.trim()).is_some() {
                        return Err(err("duplicate action argument"));
                    }
                }
                let mut get = |key| {
                    fields
                        .remove(key)
                        .ok_or_else(|| err(format!("missing action argument {key}")))
                };
                let action = match kind.trim() {
                    "notice" => {
                        let severity = text(get("severity")?)?;
                        let message = text(get("message")?)?;
                        if !["info", "warning", "high", "critical"].contains(&severity.as_str()) {
                            return Err(err("invalid notice severity"));
                        }
                        Action::Notice { severity, message }
                    }
                    "tag" => Action::Tag {
                        name: text(get("name")?)?,
                        value: text(get("value")?)?,
                    },
                    "metric" => {
                        let name = text(get("name")?)?;
                        let value = get("value")?
                            .parse()
                            .map_err(|_| err("metric increment must be u64"))?;
                        if !identifier(&name) {
                            return Err(err("invalid metric name"));
                        }
                        metrics.insert(name.clone());
                        Action::Metric { name, value }
                    }
                    "log" => {
                        let level = text(get("level")?)?;
                        let message = text(get("message")?)?;
                        if !["debug", "info", "warning", "error"].contains(&level.as_str()) {
                            return Err(err("invalid log level"));
                        }
                        Action::Log { level, message }
                    }
                    _ => return Err(err(
                        "supported actions: notice, tag, metric, log; active actions are forbidden",
                    )),
                };
                if !fields.is_empty() {
                    return Err(err("unknown action argument"));
                }
                actions.push(action);
            }
            if actions.is_empty() {
                return Err(err("rule requires an action"));
            }
            rules.push(Rule {
                id,
                version: rule_version,
                event: event.into(),
                predicate: event::parse(predicate)?,
                actions,
            });
            rest = rest[close + 1..].trim();
        }
        if metrics.len() > 128 {
            return Err(err("at most 128 named metrics"));
        }
        Ok(Self {
            rules,
            version,
            counters: BTreeMap::new(),
            dedup: BTreeMap::new(),
            window: std::time::Instant::now(),
            notices: 0,
            suppressed: 0,
        })
    }
    pub fn evaluate(&mut self, row: &Value) -> Result<Vec<Effect>> {
        let now = std::time::Instant::now();
        if now.duration_since(self.window).as_secs() >= 1 {
            self.window = now;
            self.notices = 0;
        }
        self.dedup
            .retain(|_, at| now.duration_since(*at).as_secs() < 60);
        let mut effects = Vec::new();
        for rule in &self.rules {
            if rule.event != "*" && row["event_type"] != rule.event {
                continue;
            }
            if !rule.predicate.matches(row) {
                continue;
            }
            for (index, action) in rule.actions.iter().enumerate() {
                if effects.len() >= 128 {
                    return Err(err(
                        "more than 128 matching actions per event; narrow policies",
                    ));
                }
                let (event_type, data) = match action {
                    Action::Notice { severity, message } => {
                        let key = format!(
                            "{}:{index}:{}",
                            rule.id,
                            row["flow_id"].as_str().unwrap_or("")
                        );
                        if self.notices >= 100
                            || self.dedup.contains_key(&key)
                            || self.dedup.len() >= 4096
                        {
                            self.suppressed = self.suppressed.saturating_add(1);
                            continue;
                        }
                        self.dedup.insert(key, now);
                        self.notices += 1;
                        (
                            "notice.policy",
                            json!({"severity":severity,"message":message}),
                        )
                    }
                    Action::Tag { name, value } => {
                        ("policy.tag", json!({"name":name,"value":value}))
                    }
                    Action::Metric { name, value } => {
                        let counter = self.counters.entry(name.clone()).or_default();
                        *counter = counter
                            .checked_add(*value)
                            .ok_or_else(|| err("metric counter overflow"))?;
                        (
                            "policy.metric",
                            json!({"name":name,"increment":value,"total":counter}),
                        )
                    }
                    Action::Log { level, message } => {
                        ("policy.log", json!({"level":level,"message":message}))
                    }
                };
                effects.push(Effect {
                    event_type,
                    rule_id: rule.id.clone(),
                    rule_version: rule.version.clone(),
                    program_version: self.version.clone(),
                    data,
                });
            }
        }
        Ok(effects)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actions_types_and_suppression() {
        let mut p=Program::parse(r#"rule dns version "1" on dns.query where dns.qname == "bad.example" { notice(severity: high, message: "Suspicious DNS domain"); tag(name: "risk", value: "high"); metric(name: "dns_hits", value: 1); log(level: info, message: "Matched"); }"#).unwrap();
        let row = json!({"event_type":"dns.query","flow_id":"a","payload":{"dns":{"questions":[{"name":"bad.example"}]}}});
        assert_eq!(p.evaluate(&row).unwrap().len(), 4);
        assert_eq!(p.evaluate(&row).unwrap().len(), 3);
        assert_eq!(p.suppressed, 1);
        for bad in [
            "on dns.query where dst.port == 70000 { log(level: info, message: x); }",
            "on dns.query where * { execute(command: x); }",
            "on dns.query where * { notice(severity: high, message: x, bogus: y); }",
        ] {
            assert!(Program::parse(bad).is_err());
        }
    }
}
