//! Bounded append-only live tail. Rotating the inode avoids truncation races with readers.
use super::{err, Row};
use crepe_core::Result;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
const MAX_BYTES: usize = 6 * 1024 * 1024;
pub(super) struct Journal {
    file: File,
    pub bytes: usize,
}
impl Journal {
    pub fn create(root: &Path, batch: &str, owner: &str) -> Result<Self> {
        let temporary = root.join(format!(".hot-new-{batch}"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(err)?;
        let header = format!("{batch} {owner}\n");
        file.write_all(header.as_bytes()).map_err(err)?;
        fs::rename(temporary, root.join(".hot.jsonl")).map_err(err)?;
        Ok(Self {
            file,
            bytes: header.len(),
        })
    }
    pub fn append(&mut self, row: &[u8]) -> Result<()> {
        if self.bytes + row.len() + 1 > MAX_BYTES {
            return Err(err("live journal exceeds 6 MiB; checkpoint required"));
        }
        self.file.write_all(row).map_err(err)?;
        self.file.write_all(b"\n").map_err(err)?;
        self.bytes += row.len() + 1;
        Ok(())
    }
}
pub(super) struct Snapshot {
    pub batch: String,
    pub rows: Vec<Row>,
}
pub(super) fn snapshot(root: &Path) -> Result<Option<Snapshot>> {
    let path = root.join(".hot.jsonl");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(value) => value,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(err(e)),
    };
    if !metadata.file_type().is_file() {
        return Err(err("unexpected live journal entry"));
    }
    // Ignore abandoned journals after a hard crash. Readers never modify the lock inode.
    let lock = File::open(root.join("writer.lock")).map_err(err)?;
    match lock.try_lock_shared() {
        Ok(()) => return Ok(None),
        Err(std::fs::TryLockError::WouldBlock) => {}
        Err(error) => return Err(err(error)),
    }
    let mut ownership = String::new();
    (&lock)
        .take(512)
        .read_to_string(&mut ownership)
        .map_err(err)?;
    let Some(owner) = ownership.split_whitespace().nth(2) else {
        return Ok(None);
    };
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(err(e)),
    };
    let mut data = Vec::new();
    file.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut data)
        .map_err(err)?;
    if data.len() > MAX_BYTES {
        return Err(err("live journal size limit"));
    }
    let mut lines = data.split_inclusive(|b| *b == b'\n');
    let header = lines
        .next()
        .ok_or_else(|| err("missing live journal identity"))?;
    let header = std::str::from_utf8(header).map_err(err)?;
    let mut fields = header.split_whitespace();
    let batch = fields
        .next()
        .ok_or_else(|| err("missing live batch identity"))?;
    if fields.next() != Some(owner) {
        return Ok(None);
    }
    if batch.len() != 64 || !batch.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(err("invalid live journal identity"));
    }
    let mut rows = Vec::new();
    for line in lines {
        // An append can be in flight. Only newline-terminated records are complete.
        if line.last() != Some(&b'\n') {
            break;
        }
        if line.len() > 1024 * 1024 + 1 || rows.len() >= 10_000 {
            return Err(err("live journal record limit"));
        }
        rows.push(serde_json::from_slice(line).map_err(err)?);
    }
    Ok(Some(Snapshot {
        batch: batch.into(),
        rows,
    }))
}
