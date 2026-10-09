//! Versioned built-in module manifests and dependency resolution before startup.
use crate::{Config, Profile};
use crepe_core::{Error, Result};
use serde::Serialize;
use std::collections::BTreeSet;
#[derive(Serialize)]
pub struct Manifest {
    pub name: &'static str,
    pub version: &'static str,
    pub api_version: u16,
    pub dependencies: &'static [&'static str],
    pub input_events: &'static [&'static str],
    pub output_events: &'static [&'static str],
    pub permissions: &'static [&'static str],
    pub configuration: serde_json::Value,
}
pub fn manifests() -> Vec<Manifest> {
    [
        ("packet", &[][..], &["capture.record"][..], &["packet"][..]),
        ("flow", &["packet"][..], &["packet"][..], &["flow.end"][..]),
        (
            "ip-reassembly",
            &["packet"][..],
            &["packet"][..],
            &["ip.datagram"][..],
        ),
        (
            "tcp-stream",
            &["flow", "ip-reassembly"][..],
            &["ip.datagram"][..],
            &["stream.data"][..],
        ),
        (
            "dns",
            &["tcp-stream"][..],
            &["ip.datagram", "stream.data"][..],
            &["dns.query", "dns.response"][..],
        ),
        (
            "tls",
            &["tcp-stream"][..],
            &["stream.data"][..],
            &["tls.client_hello", "tls.server_hello"][..],
        ),
        (
            "http",
            &["tcp-stream"][..],
            &["stream.data"][..],
            &["http.request", "http.response"][..],
        ),
        (
            "ssh",
            &["tcp-stream"][..],
            &["stream.data"][..],
            &["ssh.banner"][..],
        ),
        (
            "files",
            &["http"][..],
            &["stream.data"][..],
            &["file.metadata"][..],
        ),
        (
            "collector",
            &[][..],
            &["export.datagram"][..],
            &["flow.export", "export.options"][..],
        ),
        ("intel", &[][..], &["observation"][..], &["intel.match"][..]),
        ("notices", &[][..], &["observation"][..], &["notice.*"][..]),
        (
            "policy",
            &[][..],
            &["observation"][..],
            &["notice.policy", "policy.tag", "policy.metric", "policy.log"][..],
        ),
    ]
    .into_iter()
    .map(
        |(name, dependencies, input_events, output_events)| Manifest {
            name,
            version: env!("CARGO_PKG_VERSION"),
            api_version: 1,
            dependencies,
            input_events,
            output_events,
            permissions: &[],
            configuration: serde_json::json!({}),
        },
    )
    .collect()
}
#[derive(Serialize)]
pub struct Plan {
    pub modules: Vec<String>,
    pub manifests: Vec<Manifest>,
    pub raw_retention: bool,
    pub raw_policy: crate::raw::Policy,
    pub max_streams: usize,
    pub max_buffer_bytes: usize,
    pub workers: usize,
    pub lifecycle: &'static [&'static str],
}
pub fn resolve(c: &Config) -> Result<Plan> {
    let mut enabled = BTreeSet::new();
    let catalog = manifests();
    let profiles = if c.profiles.is_empty() {
        vec![c.profile]
    } else {
        c.profiles.clone()
    };
    for p in profiles {
        match p {
            Profile::Sucre => {
                enabled.insert("packet".to_string());
            }
            Profile::Banane => {
                enabled.insert("collector".to_string());
            }
            _ => {
                for m in [
                    "packet", "flow", "dns", "tls", "http", "ssh", "files", "intel", "notices",
                    "policy",
                ] {
                    enabled.insert(m.into());
                }
                if matches!(p, Profile::Complete) {
                    enabled.insert("collector".into());
                }
            }
        }
    }
    for name in c.enabled_modules.iter().chain(&c.disabled_modules) {
        if !catalog.iter().any(|m| m.name == name) {
            return Err(Error::new(
                "CREPE-CONFIG-001",
                format!("unknown module {name}; use crepe plan"),
            ));
        }
    }
    enabled.extend(c.enabled_modules.iter().cloned());
    for name in &c.disabled_modules {
        enabled.remove(name);
    }
    if !c.notices {
        enabled.remove("notices");
    }
    loop {
        let before = enabled.len();
        for m in &catalog {
            if enabled.contains(m.name) {
                for dependency in m.dependencies {
                    if c.disabled_modules.iter().any(|s| s == dependency) {
                        return Err(Error::new("CREPE-CONFIG-001",format!("module {} requires disabled {dependency}; enable {dependency} or disable {}",m.name,m.name)));
                    }
                    enabled.insert((*dependency).into());
                }
            }
        }
        if before == enabled.len() {
            break;
        }
    }
    Ok(Plan {
        modules: enabled.iter().cloned().collect(),
        manifests: catalog
            .into_iter()
            .filter(|m| enabled.contains(m.name))
            .map(|mut m| {
                m.configuration = match m.name {
                    "packet" => serde_json::json!({"workers":c.workers,"tolerant_decode":c.tolerant_decode,"raw":c.raw}),
                    "dns" => serde_json::json!({"dns_port":c.dns_port}),
                    "tcp-stream" | "ip-reassembly" => serde_json::json!({"max_streams":c.max_streams,"max_buffer_bytes":c.max_buffer_bytes}),
                    "collector" => serde_json::json!({"listen":c.collector_listen}),
                    "intel" => serde_json::json!({"feed":c.intel_feed}),
                    "policy" => serde_json::json!({"rules":c.policy_rules}),
                    "notices" => serde_json::json!({"enabled":c.notices,"deduplicate_seconds":60,"rate_per_second":100}),
                    _ => serde_json::json!({}),
                };
                m
            })
            .collect(),
        raw_retention: c.raw.enabled,
        raw_policy: c.raw.clone(),
        max_streams: c.max_streams,
        max_buffer_bytes: c.max_buffer_bytes,
        workers: c.workers,
        lifecycle: &[
            "discover",
            "validate",
            "configure",
            "start",
            "drain",
            "stop",
        ],
    })
}
