use crepe_core::{Error, Result};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Sucre,
    #[serde(alias = "choclate")]
    Chocolate,
    Banane,
    Suzette,
    Maison,
    #[default]
    Complete,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub schema_version: u16,
    pub sensor: String,
    pub profile: Profile,
    pub max_streams: usize,
    pub workers: usize,
    pub max_buffer_bytes: usize,
    pub dns_port: u16,
    pub notices: bool,
    pub tolerant_decode: bool,
    pub interface: Option<String>,
    pub collector_listen: Option<std::net::SocketAddr>,
    pub store: Option<std::path::PathBuf>,
    pub flair: bool,
    pub intel_feed: Option<std::path::PathBuf>,
    pub plugins: Vec<std::path::PathBuf>,
    pub policy_rules: Option<std::path::PathBuf>,
    pub disabled_modules: Vec<String>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: 1,
            sensor: "local".into(),
            profile: Profile::Complete,
            max_streams: 1024,
            workers: 1,
            max_buffer_bytes: 4194304,
            dns_port: 53,
            notices: true,
            tolerant_decode: false,
            interface: None,
            collector_listen: None,
            store: None,
            flair: true,
            intel_feed: None,
            plugins: Vec::new(),
            policy_rules: None,
            disabled_modules: Vec::new(),
        }
    }
}
impl Config {
    pub fn parse(text: &str) -> Result<Self> {
        if text.len() > 65536 {
            return Err(Error::new(
                "CREPE-CONFIG-001",
                "configuration exceeds 64 KiB",
            ));
        }
        let c: Self = toml::from_str(text).map_err(|e| Error::new("CREPE-CONFIG-001", e))?;
        c.validate()?;
        Ok(c)
    }
    /// Apply one strict flat-TOML layer without resetting unspecified settings.
    pub fn overlay(&self, text: &str) -> Result<Self> {
        if text.len() > 65536 {
            return Err(Error::new(
                "CREPE-CONFIG-001",
                "configuration exceeds 64 KiB",
            ));
        }
        let layer: toml::Table =
            toml::from_str(text).map_err(|e| Error::new("CREPE-CONFIG-001", e))?;
        let mut base =
            toml::Value::try_from(self).map_err(|e| Error::new("CREPE-CONFIG-001", e))?;
        base.as_table_mut()
            .expect("config serializes to a table")
            .extend(layer);
        let result: Self = base
            .try_into()
            .map_err(|e| Error::new("CREPE-CONFIG-001", e))?;
        result.validate()?;
        Ok(result)
    }
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.sensor.is_empty()
            || self.sensor.len() > 64
            || !self
                .sensor
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || !(1..=16).contains(&self.workers)
            || self.max_streams < self.workers
            || self.max_buffer_bytes < self.workers
            || self.max_streams == 0
            || self.max_streams > 65536
            || self.max_buffer_bytes == 0
            || self.max_buffer_bytes > 268435456
            || self.dns_port == 0
            || self.plugins.len() > 4
            || self
                .interface
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.len() > 256 || s.contains('\0'))
            || self
                .disabled_modules
                .iter()
                .any(|s| !["dns", "tls", "http", "ssh", "files", "notices"].contains(&s.as_str()))
        {
            return Err(Error::new(
                "CREPE-CONFIG-001",
                "invalid schema, sensor or resource limits",
            ));
        }
        Ok(())
    }
    pub fn packets(&self) -> bool {
        matches!(
            self.profile,
            Profile::Sucre
                | Profile::Chocolate
                | Profile::Suzette
                | Profile::Maison
                | Profile::Complete
        )
    }
    pub fn flows(&self) -> bool {
        matches!(
            self.profile,
            Profile::Chocolate | Profile::Suzette | Profile::Maison | Profile::Complete
        )
    }
    pub fn analysis(&self) -> bool {
        matches!(
            self.profile,
            Profile::Chocolate | Profile::Suzette | Profile::Maison | Profile::Complete
        )
    }
    pub fn accepts(&self, kind: &str) -> bool {
        !matches!(self.profile, Profile::Banane)
            && (self.notices || !kind.starts_with("notice."))
            && !self.disabled_modules.iter().any(|m| {
                kind.starts_with(&format!(
                    "{}.",
                    match m.as_str() {
                        "files" => "file",
                        "notices" => "notice",
                        _ => m,
                    }
                ))
            })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_configuration() {
        assert!(Config::parse("sensor='lab-1'\nprofile='suzette'")
            .unwrap()
            .analysis());
        for c in [
            "sensor='../oops'",
            "schema_version=2",
            "max_streams=0",
            "unknown=true",
            "profile='imaginary'",
        ] {
            assert!(Config::parse(c).is_err(), "{c}");
        }
    }
}
