//! Atomic, append-only Parquet batches with bounded DataFusion reads.
mod functions;
mod hot;
mod maintenance;
pub use maintenance::{compact, compact_classes, Compaction};
mod query;
use crepe_core::{Error, Result};
use datafusion::{
    arrow::{
        array::{ArrayRef, Int64Array, StringArray, UInt64Array},
        datatypes::{DataType, Field, Schema},
        json::LineDelimitedWriter,
        record_batch::RecordBatch,
    },
    execution::{memory_pool::GreedyMemoryPool, runtime_env::RuntimeEnvBuilder},
    prelude::*,
};
use futures::TryStreamExt;
use parquet::arrow::ArrowWriter;
pub use query::compile;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
const SCHEMA_VERSION: u16 = 2;
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub event_id: String,
    pub flow_id: String,
    /// Tuple-level identity, distinct from a connection instance.
    #[serde(default)]
    pub conversation_id: String,
    /// instance, unassigned, or exported; absent in legacy stores.
    #[serde(default)]
    pub identity_status: String,
    pub sensor: String,
    pub source: String,
    pub timestamp_ns: Option<String>,
    pub timestamp_ms: Option<i64>,
    pub event_type: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u64>,
    pub dst_port: Option<u64>,
    pub proto: Option<String>,
    pub packets: Option<u64>,
    pub bytes: Option<u64>,
    pub payload: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u16,
}
fn err(e: impl std::fmt::Display) -> Error {
    Error::new("CREPE-STORE-001", e)
}
pub fn identity(parts: &[&str]) -> String {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p.as_bytes());
    }
    h.finalize().to_hex().to_string()
}
pub fn hash_file(path: &Path) -> Result<String> {
    let mut f = File::open(path).map_err(err)?;
    let mut h = blake3::Hasher::new();
    let mut b = [0; 65536];
    loop {
        let n = f.read(&mut b).map_err(err)?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    Ok(h.finalize().to_hex().to_string())
}
fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("event_id", DataType::Utf8, false),
        Field::new("flow_id", DataType::Utf8, false),
        Field::new("conversation_id", DataType::Utf8, true),
        Field::new("identity_status", DataType::Utf8, true),
        Field::new("sensor", DataType::Utf8, false),
        Field::new("source", DataType::Utf8, false),
        Field::new("timestamp_ns", DataType::Utf8, true),
        Field::new("timestamp_ms", DataType::Int64, true),
        Field::new("event_type", DataType::Utf8, false),
        Field::new("src_ip", DataType::Utf8, true),
        Field::new("dst_ip", DataType::Utf8, true),
        Field::new("src_port", DataType::UInt64, true),
        Field::new("dst_port", DataType::UInt64, true),
        Field::new("proto", DataType::Utf8, true),
        Field::new("packets", DataType::UInt64, true),
        Field::new("bytes", DataType::UInt64, true),
        Field::new("payload", DataType::Utf8, false),
    ]))
}
fn batch(rows: &[Row]) -> Result<RecordBatch> {
    macro_rules! strings {
        ($field:ident) => {
            Arc::new(StringArray::from(
                rows.iter().map(|r| r.$field.as_str()).collect::<Vec<_>>(),
            )) as ArrayRef
        };
    }
    macro_rules! optional {
        ($field:ident) => {
            Arc::new(StringArray::from(
                rows.iter().map(|r| r.$field.as_deref()).collect::<Vec<_>>(),
            )) as ArrayRef
        };
    }
    macro_rules! nums {
        ($field:ident) => {
            Arc::new(UInt64Array::from(
                rows.iter().map(|r| r.$field).collect::<Vec<_>>(),
            )) as ArrayRef
        };
    }
    RecordBatch::try_new(
        schema(),
        vec![
            strings!(event_id),
            strings!(flow_id),
            strings!(conversation_id),
            strings!(identity_status),
            strings!(sensor),
            strings!(source),
            optional!(timestamp_ns),
            Arc::new(Int64Array::from(
                rows.iter().map(|r| r.timestamp_ms).collect::<Vec<_>>(),
            )),
            strings!(event_type),
            optional!(src_ip),
            optional!(dst_ip),
            nums!(src_port),
            nums!(dst_port),
            optional!(proto),
            nums!(packets),
            nums!(bytes),
            strings!(payload),
        ],
    )
    .map_err(err)
}
pub fn schema_version(root: &Path) -> Result<u16> {
    let data = fs::read(root.join("schema.json")).map_err(err)?;
    if data.len() > 4096 {
        return Err(err("manifest size limit"));
    }
    let manifest: Manifest = serde_json::from_slice(&data).map_err(err)?;
    if ![1, SCHEMA_VERSION].contains(&manifest.schema_version) {
        return Err(err("unsupported store schema; explicit migration required"));
    }
    Ok(manifest.schema_version)
}
fn validate_root(root: &Path) -> Result<()> {
    schema_version(root).map(|_| ())
}
fn validate_writable(root: &Path) -> Result<()> {
    if schema_version(root)? != SCHEMA_VERSION {
        return Err(err("schema-1 history is read-only: reimport original captures into a NEW schema-2 store; old tuple IDs cannot be safely migrated into connection instances"));
    }
    Ok(())
}
/// Persistent lock inode prevents unlink/reopen races; the OS releases ownership on crash.
pub(crate) struct StoreLock(File, String);
impl StoreLock {
    pub(crate) fn acquire(root: &Path) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join("writer.lock"))
            .map_err(err)?;
        file.try_lock()
            .map_err(|e| err(format!("store writer lock: {e}")))?;
        let mut previous = String::new();
        (&file)
            .take(1024)
            .read_to_string(&mut previous)
            .map_err(err)?;
        if !previous.is_empty() && !previous.starts_with("crepe-lock-v1 ") {
            return Err(err("legacy writer lock: confirm the old writer is stopped, then remove its lock manually"));
        }
        use std::io::{Seek, SeekFrom};
        file.set_len(0).map_err(err)?;
        file.seek(SeekFrom::Start(0)).map_err(err)?;
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let owner = identity(&[
            &std::process::id().to_string(),
            &format!("{:?}", std::time::SystemTime::now()),
            &NEXT
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                .to_string(),
        ]);
        writeln!(file, "crepe-lock-v1 {} {owner}", std::process::id()).map_err(err)?;
        file.sync_all().map_err(err)?;
        Ok(Self(file, owner))
    }
}
impl Drop for StoreLock {
    fn drop(&mut self) {
        let _ = self.0.set_len(0);
    }
}

pub struct Writer {
    root: PathBuf,
    stage: PathBuf,
    destination: PathBuf,
    _lock: StoreLock,
    hot: Option<hot::Journal>,
    rows: Vec<Row>,
    bytes: usize,
    parts: usize,
    committed: bool,
    pub count: u64,
}
impl Writer {
    /// A source ID must be a 64-character hash. One writer per store; readers see committed batches.
    pub fn begin(root: &Path, id: &str) -> Result<Self> {
        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(err("batch ID must be a hex hash"));
        }
        fs::create_dir_all(root).map_err(err)?;
        let guard = StoreLock::acquire(root)?;
        // Only abandoned staging directories have this exact reserved name shape.
        for entry in fs::read_dir(root).map_err(err)? {
            let entry = entry.map_err(err)?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name
                .strip_prefix(".hot-new-")
                .is_some_and(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                if !entry.file_type().map_err(err)?.is_file() {
                    return Err(err("unexpected hot staging entry type"));
                }
                fs::remove_file(entry.path()).map_err(err)?;
            }
            if name
                .strip_prefix(".staging-")
                .is_some_and(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                if !entry.file_type().map_err(err)?.is_dir() {
                    return Err(err("unexpected staging entry type"));
                }
                fs::remove_dir_all(entry.path()).map_err(err)?;
            }
        }
        let stage = root.join(format!(".staging-{id}"));
        let destination = root.join("data").join(id);
        let result = (|| {
            if root.join("schema.json").exists() {
                validate_writable(root)?
            } else {
                let temp = root.join(".schema.tmp");
                let mut f = File::create(&temp).map_err(err)?;
                f.write_all(
                    &serde_json::to_vec(&Manifest {
                        schema_version: SCHEMA_VERSION,
                    })
                    .map_err(err)?,
                )
                .map_err(err)?;
                f.sync_all().map_err(err)?;
                fs::rename(temp, root.join("schema.json")).map_err(err)?;
            }
            if destination.exists() {
                return Err(err("source batch already ingested (idempotency guard)"));
            }
            fs::create_dir_all(root.join("data")).map_err(err)?;
            fs::create_dir(&stage).map_err(err)?;
            Ok(())
        })();
        result?;
        Ok(Self {
            root: root.into(),
            stage,
            destination,
            _lock: guard,
            hot: None,
            rows: vec![],
            bytes: 0,
            parts: 0,
            committed: false,
            count: 0,
        })
    }
    /// Opt live sessions into queryable unpublished observations; offline imports stay atomic.
    pub fn enable_hot_queries(&mut self) -> Result<()> {
        let id = self
            .destination
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| err("invalid batch identity"))?;
        self.hot = Some(hot::Journal::create(&self.root, id, &self._lock.1)?);
        Ok(())
    }
    pub fn hot_bytes(&self) -> usize {
        self.hot.as_ref().map_or(0, |hot| hot.bytes)
    }
    pub fn push(&mut self, row: Row) -> Result<()> {
        let encoded = serde_json::to_vec(&row).map_err(err)?;
        let size = encoded.len();
        if size > 1024 * 1024 {
            return Err(err("row exceeds 1 MiB"));
        }
        if self.hot.is_some() && self.hot_bytes() + size + 1 > 4 * 1024 * 1024 {
            let next = identity(&[
                "hot-capacity",
                &self.destination.to_string_lossy(),
                &self.count.to_string(),
            ]);
            self.checkpoint(&next)?;
        }
        if !self.rows.is_empty() && (self.rows.len() >= 1024 || self.bytes + size > 4 * 1024 * 1024)
        {
            self.flush()?
        }
        if let Some(hot) = &mut self.hot {
            hot.append(&encoded)?;
        }
        self.bytes += size;
        self.rows.push(row);
        self.count += 1;
        Ok(())
    }
    fn flush(&mut self) -> Result<()> {
        if self.rows.is_empty() {
            return Ok(());
        }
        let mut groups = std::collections::BTreeMap::<String, Vec<Row>>::new();
        for row in self.rows.drain(..) {
            let kind = if row.event_type.len() <= 64
                && !row.event_type.is_empty()
                && row
                    .event_type
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                row.event_type.clone()
            } else {
                format!("custom-{}", &identity(&[&row.event_type])[..16])
            };
            let hour = row
                .timestamp_ms
                .map(|t| t.div_euclid(3_600_000).to_string())
                .unwrap_or_else(|| "unknown".into());
            let mut key = format!("event={kind}/hour={hour}");
            if groups.len() >= 16 && !groups.contains_key(&key) {
                key = "event=mixed/hour=unknown".into();
            }
            groups.entry(key).or_default().push(row);
        }
        for (partition, rows) in groups {
            let directory = self.stage.join(partition);
            fs::create_dir_all(&directory).map_err(err)?;
            let path = directory.join(format!("{:08}.parquet", self.parts));
            let f = File::create(&path).map_err(err)?;
            let properties = parquet::file::properties::WriterProperties::builder()
                .set_compression(parquet::basic::Compression::ZSTD(Default::default()))
                .build();
            let mut w = ArrowWriter::try_new(f, schema(), Some(properties)).map_err(err)?;
            w.write(&batch(&rows)?).map_err(err)?;
            w.close().map_err(err)?;
            File::open(path).map_err(err)?.sync_all().map_err(err)?;
            let mut parent = Some(directory.as_path());
            while let Some(path) = parent {
                File::open(path).map_err(err)?.sync_all().map_err(err)?;
                if path == self.stage {
                    break;
                }
                parent = path.parent();
            }
            self.parts += 1;
        }
        self.bytes = 0;
        Ok(())
    }
    /// Publish a live batch while retaining exclusive writer ownership.
    /// Previously published checkpoints survive subsequent session failures.
    pub fn checkpoint(&mut self, next_id: &str) -> Result<()> {
        if next_id.len() != 64 || !next_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(err("checkpoint ID must be a hex hash"));
        }
        let next_stage = self.root.join(format!(".staging-{next_id}"));
        let next_destination = self.root.join("data").join(next_id);
        if next_stage.exists() || next_destination.exists() {
            return Err(err("checkpoint already exists"));
        }
        self.flush()?;
        File::open(&self.stage)
            .map_err(err)?
            .sync_all()
            .map_err(err)?;
        fs::rename(&self.stage, &self.destination).map_err(err)?;
        File::open(self.root.join("data"))
            .map_err(err)?
            .sync_all()
            .map_err(err)?;
        fs::create_dir(&next_stage).map_err(err)?;
        self.stage = next_stage;
        self.destination = next_destination;
        self.parts = 0;
        if self.hot.is_some() {
            self.hot = Some(hot::Journal::create(&self.root, next_id, &self._lock.1)?);
        }
        Ok(())
    }
    pub fn commit(mut self) -> Result<u64> {
        self.flush()?;
        File::open(&self.stage)
            .map_err(err)?
            .sync_all()
            .map_err(err)?;
        fs::rename(&self.stage, &self.destination).map_err(err)?;
        File::open(self.root.join("data"))
            .map_err(err)?
            .sync_all()
            .map_err(err)?;
        self.committed = true;
        Ok(self.count)
    }
}
impl Drop for Writer {
    fn drop(&mut self) {
        if self.hot.is_some() {
            let _ = fs::remove_file(self.root.join(".hot.jsonl"));
        }
        if !self.committed {
            let _ = fs::remove_dir_all(&self.stage);
        }
    }
}
pub fn query(root: &Path, cql: &str, output: &mut impl Write) -> Result<usize> {
    let sql = compile(cql)?;
    query_sql(root, &sql, output)
}
fn query_sql(root: &Path, sql: &str, output: &mut impl Write) -> Result<usize> {
    execute_query(Some(root), None, sql, output)
}
/// Evaluate the historical CQL grammar over one bounded live processing window.
pub fn query_rows(rows: &[Row], cql: &str, output: &mut impl Write) -> Result<usize> {
    if rows.len() > 10_000 {
        return Err(err("live query window exceeds 10000 rows"));
    }
    let mut bytes = 0_usize;
    for row in rows {
        bytes += serde_json::to_vec(row).map_err(err)?.len();
        if bytes > 16 * 1024 * 1024 {
            return Err(err("live query window exceeds 16 MiB"));
        }
    }
    execute_query(None, Some(rows), &compile(cql)?, output)
}
fn execute_query(
    root: Option<&Path>,
    rows: Option<&[Row]>,
    sql: &str,
    output: &mut impl Write,
) -> Result<usize> {
    if let Some(root) = root {
        validate_root(root)?;
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(err)?;
    rt.block_on(async {
        let runtime = Arc::new(
            RuntimeEnvBuilder::new()
                .with_memory_pool(Arc::new(GreedyMemoryPool::new(256 * 1024 * 1024)))
                .build()
                .map_err(err)?,
        );
        let ctx = SessionContext::new_with_config_rt(
            SessionConfig::new()
                .set_bool(
                    "datafusion.execution.listing_table_ignore_subdirectory",
                    false,
                )
                .with_target_partitions(2)
                .with_batch_size(1024),
            runtime,
        );
        functions::register(&ctx);
        if let Some(root) = root {
            // Read the immutable journal inode first, then freeze the published batch list.
            // If its batch was published meanwhile, the Parquet copy wholly supersedes it.
            let mut hot = hot::snapshot(root)?;
            let mut paths = Vec::new();
            for entry in fs::read_dir(root.join("data")).map_err(err)? {
                let entry = entry.map_err(err)?;
                if !entry.file_type().map_err(err)?.is_dir() {
                    continue;
                }
                if hot
                    .as_ref()
                    .is_some_and(|h| entry.file_name().to_str() == Some(h.batch.as_str()))
                {
                    hot = None;
                }
                if fs::read_dir(entry.path()).map_err(err)?.next().is_some() {
                    paths.push(
                        entry
                            .path()
                            .to_str()
                            .ok_or_else(|| err("store path is not UTF-8"))?
                            .to_string(),
                    );
                    if paths.len() > 100_000 {
                        return Err(err("query batch limit"));
                    }
                }
            }
            if !paths.is_empty() {
                let frame = ctx
                    .read_parquet(
                        paths,
                        ParquetReadOptions::default().schema(schema().as_ref()),
                    )
                    .await
                    .map_err(err)?;
                ctx.register_table("events", frame.into_view())
                    .map_err(err)?;
            } else {
                ctx.register_batch("events", RecordBatch::new_empty(schema()))
                    .map_err(err)?;
            }
            if let Some(hot) = hot.filter(|hot| !hot.rows.is_empty()) {
                ctx.register_batch("hot_events", batch(&hot.rows)?)
                    .map_err(err)?;
                let union = ctx
                    .sql("SELECT * FROM events UNION ALL SELECT * FROM hot_events")
                    .await
                    .map_err(err)?;
                ctx.deregister_table("events").map_err(err)?;
                ctx.register_table("events", union.into_view())
                    .map_err(err)?;
            }
        } else {
            ctx.register_batch("events", batch(rows.unwrap_or_default())?)
                .map_err(err)?;
        }
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let df = ctx.sql(sql).await.map_err(err)?;
            let mut stream = df.execute_stream().await.map_err(err)?;
            let mut writer = LineDelimitedWriter::new(output);
            let mut count = 0;
            while let Some(batch) = stream.try_next().await.map_err(err)? {
                count += batch.num_rows();
                writer.write(&batch).map_err(err)?;
            }
            writer.finish().map_err(err)?;
            Ok(count)
        })
        .await
        .map_err(|_| err("query exceeded 30 seconds"))?
    })
}

/// Hold the existing store writer lock for raw-only maintenance.
pub fn exclusive<T>(root: &Path, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    validate_writable(root)?;
    let _guard = StoreLock::acquire(root)?;
    operation()
}
