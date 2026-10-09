//! Offline, bounded indicator matching and observational rules. No active actions.
pub mod cpl;
use crepe_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::IpAddr};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Indicator {
    pub kind: String,
    pub value: String,
    pub source: String,
    #[serde(default = "warning")]
    pub severity: String,
}
fn warning() -> String {
    "warning".into()
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub event_type: String,
    pub field: String,
    pub equals: String,
    pub message: String,
    #[serde(default = "warning")]
    pub severity: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub event_type: &'static str,
    pub code: &'static str,
    pub severity: String,
    pub source: String,
    pub source_version: String,
    pub field: String,
    pub value: String,
    pub message: String,
}
#[derive(Default)]
pub struct Engine {
    exact: BTreeMap<(String, String), Vec<Indicator>>,
    networks: Vec<(ipnet::IpNet, Indicator)>,
    rules: Vec<Rule>,
    pub cpl: Option<cpl::Program>,
    feed_version: String,
    rules_version: String,
}
fn error(message: impl std::fmt::Display) -> Error {
    Error::new("CREPE-INTEL-001", message)
}
fn severity(s: &str) -> bool {
    ["info", "warning", "high"].contains(&s)
}
fn domain(value: &str) -> Result<String> {
    let value = value.trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 253
        || value.split('.').any(|p| {
            p.is_empty()
                || p.len() > 63
                || !p
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        })
    {
        return Err(error("invalid ASCII domain indicator"));
    }
    Ok(value)
}
pub fn normalize_url(value: &str) -> Result<String> {
    let mut url = url::Url::parse(value).map_err(error)?;
    if !["http", "https"].contains(&url.scheme())
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(error(
            "URL indicator requires HTTP(S), a host and no user credentials",
        ));
    }
    url.set_fragment(None);
    Ok(url.into())
}
fn lines<T: for<'de> Deserialize<'de>>(text: &str, limit: usize) -> Result<Vec<T>> {
    if text.len() > 8 * 1024 * 1024 {
        return Err(error("feed exceeds 8 MiB"));
    }
    let mut rows = Vec::new();
    for line in text.lines().filter(|s| !s.trim().is_empty()) {
        if rows.len() == limit || line.len() > 4096 {
            return Err(error("feed record limit exceeded"));
        }
        rows.push(serde_json::from_str(line).map_err(error)?);
    }
    Ok(rows)
}
impl Engine {
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty()
            && self.networks.is_empty()
            && self.rules.is_empty()
            && self.cpl.is_none()
    }
    pub fn new(indicators: &str, rules: &str) -> Result<Self> {
        let mut engine = Self {
            feed_version: blake3::hash(indicators.as_bytes()).to_hex().to_string(),
            rules_version: blake3::hash(rules.as_bytes()).to_hex().to_string(),
            ..Default::default()
        };
        for mut entry in lines::<Indicator>(indicators, 65536)? {
            if entry.source.is_empty() || entry.source.len() > 256 || !severity(&entry.severity) {
                return Err(error("invalid source or severity"));
            }
            match entry.kind.as_str() {
                "ip" => entry.value = entry.value.parse::<IpAddr>().map_err(error)?.to_string(),
                "domain" => entry.value = domain(&entry.value)?,
                "url" => entry.value = normalize_url(&entry.value)?,
                "sha256" => {
                    if entry.value.len() != 64
                        || !entry.value.bytes().all(|b| b.is_ascii_hexdigit())
                    {
                        return Err(error("invalid SHA-256 indicator"));
                    }
                    entry.value.make_ascii_lowercase();
                }
                "cidr" => {
                    if engine.networks.len() == 512 {
                        return Err(error("CIDR indicator limit is 512"));
                    }
                    engine
                        .networks
                        .push((entry.value.parse().map_err(error)?, entry));
                    continue;
                }
                _ => {
                    return Err(error(
                        "indicator kind must be ip, domain, url, cidr or sha256",
                    ))
                }
            }
            let entries = engine
                .exact
                .entry((entry.kind.clone(), entry.value.clone()))
                .or_default();
            if entries.len() == 8 {
                return Err(error("at most eight sources per indicator"));
            }
            entries.push(entry);
        }
        if rules.trim_start().starts_with("on ") || rules.trim_start().starts_with("rule ") {
            engine.cpl = Some(cpl::Program::parse(rules)?);
        } else {
            engine.rules = lines::<Rule>(rules, 256)?;
        }
        for rule in &engine.rules {
            if rule.id.is_empty()
                || rule.id.len() > 128
                || rule.event_type.len() > 128
                || rule.message.len() > 512
                || !severity(&rule.severity)
                || ![
                    "src.ip",
                    "dst.ip",
                    "domain",
                    "sha256",
                    "anomaly.code",
                    "proto",
                ]
                .contains(&rule.field.as_str())
            {
                return Err(error("invalid observational rule"));
            }
        }
        Ok(engine)
    }
    pub fn inspect(
        &self,
        event_type: &str,
        fields: &BTreeMap<String, Vec<String>>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (field, values) in fields {
            let kind = match field.as_str() {
                "src.ip" | "dst.ip" => "ip",
                "domain" => "domain",
                "sha256" => "sha256",
                "url" => "url",
                _ => continue,
            };
            for value in values.iter().take(256) {
                let normalized = if kind == "domain" {
                    match domain(value) {
                        Ok(v) => v,
                        Err(_) => continue,
                    }
                } else if kind == "url" {
                    match normalize_url(value) {
                        Ok(v) => v,
                        Err(_) => continue,
                    }
                } else {
                    value.to_ascii_lowercase()
                };
                let mut matches: Vec<&Indicator> = self
                    .exact
                    .get(&(kind.into(), normalized.clone()))
                    .into_iter()
                    .flatten()
                    .collect();
                if let Ok(ip) = normalized.parse::<IpAddr>() {
                    matches.extend(
                        self.networks
                            .iter()
                            .filter(|(net, _)| net.contains(&ip))
                            .map(|(_, entry)| entry),
                    );
                }
                for entry in matches {
                    if findings.len() == 128 {
                        return findings;
                    }
                    findings.push(Finding {
                        event_type: "intel.match",
                        code: "CREPE-INTEL-MATCH",
                        severity: entry.severity.clone(),
                        source: entry.source.clone(),
                        source_version: self.feed_version.clone(),
                        field: field.clone(),
                        value: normalized.clone(),
                        message: "Observed indicator match; not proof of malicious activity".into(),
                    });
                }
            }
        }
        for rule in &self.rules {
            if findings.len() == 128 {
                break;
            }
            if (rule.event_type == "*" || rule.event_type == event_type)
                && fields
                    .get(&rule.field)
                    .is_some_and(|v| v.contains(&rule.equals))
            {
                findings.push(Finding {
                    event_type: "notice.policy",
                    code: "CREPE-NOTICE-POLICY",
                    severity: rule.severity.clone(),
                    source: rule.id.clone(),
                    source_version: self.rules_version.clone(),
                    field: rule.field.clone(),
                    value: rule.equals.clone(),
                    message: rule.message.clone(),
                });
            }
        }
        findings
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_domains_cidr_and_policies_are_bounded_and_passive() {
        let engine = Engine::new("{\"kind\":\"domain\",\"value\":\"Example.TEST.\",\"source\":\"test\"}\n{\"kind\":\"cidr\",\"value\":\"192.0.2.0/24\",\"source\":\"lab\"}",
            "{\"id\":\"dns-lab\",\"event_type\":\"dns.query\",\"field\":\"proto\",\"equals\":\"udp\",\"message\":\"Lab DNS\"}").unwrap();
        let fields = BTreeMap::from([
            ("domain".into(), vec!["example.test.".into()]),
            ("src.ip".into(), vec!["192.0.2.10".into()]),
            ("proto".into(), vec!["udp".into()]),
        ]);
        assert_eq!(engine.inspect("dns.query", &fields).len(), 3);
        assert_eq!(engine.inspect("tls.client_hello", &fields).len(), 2);
        assert!(engine
            .inspect(
                "dns.query",
                &BTreeMap::from([("domain".into(), vec!["notexample.test".into()])])
            )
            .is_empty());
        assert!(Engine::new(
            "{\"kind\":\"ip\",\"value\":\"oops\",\"source\":\"test\"}",
            ""
        )
        .is_err());
        assert!(Engine::new(&" ".repeat(8 * 1024 * 1024 + 1), "").is_err());
    }
}

#[cfg(test)]
mod url_tests {
    use super::*;
    #[test]
    fn url_path_case_and_feed_version_are_preserved() {
        let engine = Engine::new(
            r#"{"kind":"url","value":"http://Example.TEST/Case?q=1","source":"fixture"}"#,
            "",
        )
        .unwrap();
        let findings = engine.inspect(
            "http.request",
            &BTreeMap::from([("url".into(), vec!["http://example.test/Case?q=1".into()])]),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source_version.len(), 64);
        assert!(engine
            .inspect(
                "http.request",
                &BTreeMap::from([("url".into(), vec!["http://example.test/case?q=1".into()])])
            )
            .is_empty());
        assert!(normalize_url("file:///etc/passwd").is_err());
    }
}
