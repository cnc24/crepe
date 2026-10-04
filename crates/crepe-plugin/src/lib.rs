//! Capability-free WebAssembly components with fuel, memory and event budgets.
use crepe_core::{Error, Result};
use serde::Deserialize;
use std::path::Path;
use wasmtime::{
    component::{Component, Linker, TypedFunc},
    Config, Engine, Store, StoreLimits, StoreLimitsBuilder,
};
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub api_version: u32,
    pub name: String,
    pub component: String,
    pub subscriptions: Vec<String>,
    pub memory_bytes: usize,
    pub fuel_per_event: u64,
    pub max_events: u64,
    #[serde(default)]
    pub permissions: Vec<String>,
}
fn error(e: impl std::fmt::Display) -> Error {
    Error::new("CREPE-PLG-001", e)
}
pub struct Plugin {
    pub name: String,
    manifest: Manifest,
    store: Store<StoreLimits>,
    process: TypedFunc<(String,), (String,)>,
    events: u64,
    disabled: bool,
}
fn bounded_read(path: &Path, max: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(max + 1).read_to_end(&mut bytes))
        .map_err(error)?;
    if bytes.len() as u64 > max {
        return Err(error("plugin file exceeds size limit"));
    }
    Ok(bytes)
}
impl Plugin {
    pub fn load(path: &Path) -> Result<Self> {
        let path = path.canonicalize().map_err(error)?;
        let manifest: Manifest =
            serde_json::from_slice(&bounded_read(&path, 16384)?).map_err(error)?;
        let relative = Path::new(&manifest.component);
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err(error(
                "component must be a relative path inside its manifest directory",
            ));
        }
        let directory = path
            .parent()
            .ok_or_else(|| error("manifest has no directory"))?;
        let component = directory.join(relative).canonicalize().map_err(error)?;
        if !component.starts_with(directory) {
            return Err(error("component path escapes its manifest directory"));
        }
        Self::from_bytes(manifest, &bounded_read(&component, 1024 * 1024)?)
    }
    pub fn from_bytes(manifest: Manifest, bytes: &[u8]) -> Result<Self> {
        if manifest.api_version != 1
            || manifest.name.is_empty()
            || manifest.name.len() > 64
            || !manifest
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            || !manifest.permissions.is_empty()
            || !(65536..=16 * 1024 * 1024).contains(&manifest.memory_bytes)
            || !(1..=10_000_000).contains(&manifest.fuel_per_event)
            || !(1..=1_000_000).contains(&manifest.max_events)
            || manifest.subscriptions.is_empty()
            || manifest.subscriptions.len() > 32
            || manifest
                .subscriptions
                .iter()
                .any(|s| s.len() > 128 || s == "packet")
            || bytes.len() > 1024 * 1024
        {
            return Err(error(
                "invalid plugin manifest or unsupported permissions/API",
            ));
        }
        let mut config = Config::new();
        config
            .consume_fuel(true)
            .wasm_component_model(true)
            .max_wasm_stack(256 * 1024);
        let engine = Engine::new(&config).map_err(error)?;
        let component = Component::new(&engine, bytes).map_err(error)?;
        let limits = StoreLimitsBuilder::new()
            .memory_size(manifest.memory_bytes)
            .memories(1)
            .tables(1)
            .table_elements(1024)
            .instances(4)
            .build();
        let mut store = Store::new(&engine, limits);
        store.limiter(|s| s);
        store.set_fuel(50_000_000).map_err(error)?;
        // Empty linker deliberately grants no filesystem/network/environment/process access.
        let linker = Linker::new(&engine);
        let instance = linker.instantiate(&mut store, &component).map_err(error)?;
        let process = instance
            .get_typed_func::<(String,), (String,)>(&mut store, "process")
            .map_err(error)?;
        Ok(Self {
            name: manifest.name.clone(),
            manifest,
            store,
            process,
            events: 0,
            disabled: false,
        })
    }
    pub fn inspect(&mut self, event_type: &str, event: &str) -> Result<Vec<serde_json::Value>> {
        if self.disabled
            || event_type == "packet"
            || !self
                .manifest
                .subscriptions
                .iter()
                .any(|s| s == "*" || s == event_type)
        {
            return Ok(Vec::new());
        }
        let result = self.call(event);
        if result.is_err() {
            self.disabled = true;
        }
        result
    }
    fn call(&mut self, event: &str) -> Result<Vec<serde_json::Value>> {
        if event.len() > 65536 || self.events >= self.manifest.max_events {
            return Err(error("plugin event budget exceeded; plugin disabled"));
        }
        self.events += 1;
        self.store
            .set_fuel(self.manifest.fuel_per_event)
            .map_err(error)?;
        let (output,) = self
            .process
            .call(&mut self.store, (event.into(),))
            .map_err(error)?;
        if output.len() > 65536 {
            return Err(error("plugin output exceeds 64 KiB"));
        }
        let mut rows = Vec::new();
        for line in output.lines().filter(|l| !l.trim().is_empty()) {
            if rows.len() == 64 {
                return Err(error("plugin output exceeds 64 events"));
            }
            let row: serde_json::Value = serde_json::from_str(line).map_err(error)?;
            if !row.is_object() {
                return Err(error("plugin output must contain JSON objects"));
            }
            rows.push(row);
        }
        Ok(rows)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn manifest() -> Manifest {
        Manifest {
            api_version: 1,
            name: "test".into(),
            component: "test.wat".into(),
            subscriptions: vec!["dns.query".into()],
            memory_bytes: 65536,
            fuel_per_event: 10000,
            max_events: 2,
            permissions: vec![],
        }
    }
    fn component(body: &str) -> String {
        format!(
            r#"(component
      (core module $m
        (memory (export "memory") 1)
        (data (i32.const 16) "{{}}")
        (func (export "realloc") (param i32 i32 i32 i32) (result i32) i32.const 1024)
        (func (export "process") (param i32 i32) (result i32) {body}))
      (core instance $i (instantiate $m))
      (func (export "process") (param "event" string) (result string)
        (canon lift (core func $i "process") (memory (core memory $i "memory")) (realloc (core func $i "realloc")))))"#
        )
    }
    #[test]
    fn component_api_and_event_limits() {
        let bytes = component(
            "i32.const 0 i32.const 16 i32.store i32.const 4 i32.const 2 i32.store i32.const 0",
        );
        let mut plugin = Plugin::from_bytes(manifest(), bytes.as_bytes()).unwrap();
        assert!(plugin.inspect("packet", "{}").unwrap().is_empty());
        assert_eq!(
            plugin.inspect("dns.query", "{}").unwrap(),
            vec![serde_json::json!({})]
        );
        assert_eq!(plugin.inspect("dns.query", "{}").unwrap().len(), 1);
        assert!(plugin.inspect("dns.query", "{}").is_err());
        assert!(plugin.inspect("dns.query", "{}").unwrap().is_empty());
    }
    #[test]
    fn infinite_loops_and_memory_growth_are_contained() {
        let mut plugin = Plugin::from_bytes(
            manifest(),
            component("(loop $again br $again) i32.const 0").as_bytes(),
        )
        .unwrap();
        assert!(plugin.inspect("dns.query", "{}").is_err());
        let mut m = manifest();
        m.permissions.push("network".into());
        assert!(Plugin::from_bytes(m, component("i32.const 0").as_bytes()).is_err());
        let bytes = component("i32.const 1 memory.grow i32.const -1 i32.ne if unreachable end i32.const 0 i32.const 16 i32.store i32.const 4 i32.const 2 i32.store i32.const 0");
        assert_eq!(
            Plugin::from_bytes(manifest(), bytes.as_bytes())
                .unwrap()
                .inspect("dns.query", "{}")
                .unwrap()
                .len(),
            1
        );
    }
    #[test]
    fn manifest_paths_cannot_escape_the_plugin_bundle() {
        let root = std::env::temp_dir().join(format!("crepe-plugin-path-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("bundle")).unwrap();
        std::fs::write(root.join("outside.wat"), component("i32.const 0")).unwrap();
        let manifest = serde_json::json!({"api_version":1,"name":"test","component":"../outside.wat","subscriptions":["dns.query"],"memory_bytes":65536,"fuel_per_event":10000,"max_events":2});
        let path = root.join("bundle/manifest.json");
        std::fs::write(&path, manifest.to_string()).unwrap();
        assert!(Plugin::load(&path)
            .err()
            .unwrap()
            .message
            .contains("relative path"));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("outside.wat"), root.join("bundle/linked.wat"))
                .unwrap();
            let mut manifest = manifest;
            manifest["component"] = "linked.wat".into();
            std::fs::write(&path, manifest.to_string()).unwrap();
            assert!(Plugin::load(&path)
                .err()
                .unwrap()
                .message
                .contains("escapes"));
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
