//! Opt-in raw evidence cache. Payload lifetime is independent of historical rows.
use crepe_core::{Error, PacketRef, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
fn err(e: impl std::fmt::Display) -> Error {
    Error::new("CREPE-RAW-001", e)
}
fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(err)?
        .as_secs())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub enabled: bool,
    pub max_bytes: u64,
    pub rotate_bytes: u64,
    pub max_age_seconds: u64,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            enabled: false,
            max_bytes: 256 * 1024 * 1024,
            rotate_bytes: 16 * 1024 * 1024,
            max_age_seconds: 86400,
        }
    }
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        if self.max_bytes < 1024
            || self.max_bytes > 1024_u64.pow(4)
            || self.rotate_bytes < 1024
            || self.rotate_bytes > self.max_bytes
            || self.max_age_seconds == 0
            || self.max_age_seconds > 365 * 86400
        {
            return Err(err(
                "raw limits: 1 KiB <= rotation <= budget <= 1 TiB; age 1..31536000 seconds",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub source: String,
    pub file: String,
    pub hash: String,
    pub bytes: u64,
    pub created: u64,
    pub expires: u64,
    /// None identifies an unchanged original capture. Live chunks remap record numbers.
    pub first: Option<PacketRef>,
    pub records: u64,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    entries: Vec<Entry>,
}
fn directory(store: &Path) -> PathBuf {
    store.join("raw")
}
fn valid_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn load(store: &Path) -> Result<Manifest> {
    let path = directory(store).join("manifest.json");
    if !path.exists() {
        return Ok(Manifest::default());
    }
    if fs::metadata(&path).map_err(err)?.len() > 4 * 1024 * 1024 {
        return Err(err("raw manifest exceeds 4 MiB"));
    }
    let m: Manifest = serde_json::from_slice(&fs::read(path).map_err(err)?).map_err(err)?;
    if m.entries.len() > 4096
        || m.entries.iter().any(|e| {
            !valid_hash(&e.source)
                || !valid_hash(&e.hash)
                || (e.first.is_none() && e.source != e.hash)
                || e.file != format!("{}.pcap", e.hash)
        })
    {
        return Err(err("invalid raw manifest"));
    }
    Ok(m)
}
fn save(store: &Path, manifest: &Manifest) -> Result<()> {
    use std::io::Write;
    let dir = directory(store);
    fs::create_dir_all(&dir).map_err(err)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(err)?;
    }
    let path = dir.join("manifest.pending");
    let mut f = fs::File::create(&path).map_err(err)?;
    f.write_all(&serde_json::to_vec(manifest).map_err(err)?)
        .map_err(err)?;
    f.sync_all().map_err(err)?;
    fs::rename(path, dir.join("manifest.json")).map_err(err)?;
    Ok(())
}
/// Caller holds the store's writer lock. Only manifest-owned files can be removed.
pub fn prune_locked(store: &Path, policy: &Policy) -> Result<usize> {
    policy.validate()?;
    let mut m = load(store)?;
    let at = now()?;
    m.entries.sort_by_key(|e| e.created);
    let mut bytes: u128 = m.entries.iter().map(|e| u128::from(e.bytes)).sum();
    let mut removed = Vec::new();
    m.entries.retain(|e| {
        let remove = at >= e.expires
            || at.saturating_sub(e.created) >= policy.max_age_seconds
            || bytes > u128::from(policy.max_bytes);
        if remove {
            bytes = bytes.saturating_sub(u128::from(e.bytes));
            removed.push(e.file.clone());
        }
        !remove
    });
    save(store, &m)?;
    for file in &removed {
        if !m.entries.iter().any(|e| &e.file == file) {
            match fs::remove_file(directory(store).join(file)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(err(e)),
            }
        }
    }
    Ok(removed.len())
}
fn publish(
    store: &Path,
    source: &str,
    staged: &Path,
    first: Option<PacketRef>,
    records: u64,
    policy: &Policy,
) -> Result<()> {
    let hash = crepe_storage::hash_file(staged)?;
    let bytes = fs::metadata(staged).map_err(err)?.len();
    if bytes > policy.max_bytes {
        return Err(err("raw capture exceeds retention byte budget"));
    }
    let mut m = load(store)?;
    if m.entries.len() >= 4096 {
        return Err(err(
            "raw manifest entry limit; prune or increase rotation size",
        ));
    }
    let file = format!("{hash}.pcap");
    let destination = directory(store).join(&file);
    if destination.exists() {
        if crepe_storage::hash_file(&destination)? != hash {
            return Err(err("existing raw file hash mismatch"));
        }
    } else {
        fs::hard_link(staged, &destination).map_err(err)?;
    }
    let created = now()?;
    m.entries.push(Entry {
        source: source.into(),
        file,
        hash,
        bytes,
        created,
        expires: created.saturating_add(policy.max_age_seconds),
        first,
        records,
    });
    save(store, &m)?;
    prune_locked(store, policy)?;
    Ok(())
}
/// Retain the unchanged input, including PCAPNG metadata. The original is never deleted.
pub fn retain_file(store: &Path, source: &str, file: &Path, policy: &Policy) -> Result<()> {
    policy.validate()?;
    prune_locked(store, policy)?;
    if fs::metadata(file).map_err(err)?.len() > policy.max_bytes {
        return Err(err(
            "original capture exceeds raw byte budget; increase raw.max_bytes",
        ));
    }
    let staged = directory(store).join("original.pending");
    fs::copy(file, &staged).map_err(err)?;
    let result = (|| {
        fs::File::open(&staged)
            .map_err(err)?
            .sync_all()
            .map_err(err)?;
        if crepe_storage::hash_file(&staged)? != source {
            return Err(err("source changed while retaining capture"));
        }
        publish(store, source, &staged, None, 0, policy)
    })();
    let _ = fs::remove_file(staged);
    result
}
/// Resolve only unexpired, manifest-owned evidence. Content is verified by the reader.
pub fn locate(
    store: &Path,
    source: &str,
    reference: PacketRef,
) -> Result<Option<(PathBuf, String, u64)>> {
    let at = now()?;
    for e in load(store)?
        .entries
        .into_iter()
        .rev()
        .filter(|e| e.source == source && at < e.expires)
    {
        let sequence = match e.first {
            None => reference.sequence,
            Some(first)
                if first.section == reference.section
                    && first.interface == reference.interface
                    && reference.sequence >= first.sequence
                    && reference.sequence - first.sequence < e.records =>
            {
                reference.sequence - first.sequence + 1
            }
            _ => continue,
        };
        return Ok(Some((directory(store).join(e.file), e.hash, sequence)));
    }
    Ok(None)
}
pub struct Capture {
    store: PathBuf,
    source: String,
    policy: Policy,
    writer: Option<crepe_capture::export::Export>,
    first: Option<PacketRef>,
    last: Option<PacketRef>,
    link: u32,
    bytes: u64,
    records: u64,
    published_at: std::time::Instant,
}
impl Capture {
    pub fn new(store: &Path, source: &str, policy: &Policy) -> Result<Self> {
        policy.validate()?;
        prune_locked(store, policy)?;
        Ok(Self {
            store: store.into(),
            source: source.into(),
            policy: policy.clone(),
            writer: None,
            first: None,
            last: None,
            link: 0,
            bytes: 24,
            records: 0,
            published_at: std::time::Instant::now(),
        })
    }
    fn staged(&self) -> PathBuf {
        directory(&self.store).join("capture.pending")
    }
    pub fn push(&mut self, r: &crepe_capture::Record<'_>) -> Result<()> {
        let reference = PacketRef::from(&r.header);
        if self.writer.is_some()
            && (self.bytes + 16 + r.data.len() as u64 > self.policy.rotate_bytes
                || self.records >= 4096
                || self.link != r.linktype
                || self.last.is_some_and(|p| {
                    p.section != reference.section
                        || p.interface != reference.interface
                        || p.sequence.checked_add(1) != Some(reference.sequence)
                }))
        {
            self.rotate()?;
        }
        if self.writer.is_none() {
            let _ = fs::remove_file(self.staged());
            self.writer = Some(crepe_capture::export::Export::create(&self.staged())?);
            self.first = Some(reference);
            self.link = r.linktype;
        }
        self.writer.as_mut().unwrap().write(r)?;
        self.last = Some(reference);
        self.records += 1;
        self.bytes += 16 + r.data.len() as u64;
        Ok(())
    }
    pub fn tick(&mut self) -> Result<()> {
        if self.published_at.elapsed().as_secs() >= 5 {
            self.rotate()?;
            prune_locked(&self.store, &self.policy)?;
        }
        Ok(())
    }
    pub fn rotate(&mut self) -> Result<()> {
        self.published_at = std::time::Instant::now();
        if let Some(writer) = self.writer.take() {
            writer.finish()?;
            fs::File::open(self.staged())
                .map_err(err)?
                .sync_all()
                .map_err(err)?;
            publish(
                &self.store,
                &self.source,
                &self.staged(),
                self.first,
                self.records,
                &self.policy,
            )?;
            fs::remove_file(self.staged()).map_err(err)?;
        }
        self.bytes = 24;
        self.records = 0;
        self.first = None;
        self.last = None;
        Ok(())
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        self.writer.take();
        let _ = fs::remove_file(self.staged());
    }
}
