//! Offline store compaction/retention into a new destination; source remains intact.
use super::{err, identity, validate_root, Row, StoreLock, Writer};
use crepe_core::Result;
use datafusion::arrow::json::LineDelimitedWriter;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use serde::Serialize;
use std::{
    fs::{self, File},
    path::Path,
};
#[derive(Debug, Serialize)]
pub struct Compaction {
    pub read: u64,
    pub retained: u64,
    pub discarded: u64,
}
/// Copy a quiescent schema-2 store to a new compacted store, preserving row IDs.
/// Rows without timestamps are retained. Failed attempts remove only the new destination.
pub fn compact(source: &Path, destination: &Path, since_ms: Option<i64>) -> Result<Compaction> {
    compact_classes(source, destination, since_ms, None)
}
pub fn compact_classes(
    source: &Path,
    destination: &Path,
    since_ms: Option<i64>,
    security_since_ms: Option<i64>,
) -> Result<Compaction> {
    validate_root(source)?;
    if super::schema_version(source)? != 2 {
        return Err(super::err("schema-1 compaction requires the old release; reimport captures into a NEW schema-2 store to upgrade identity semantics"));
    }
    let source_path = source.canonicalize().map_err(err)?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let target = parent.canonicalize().map_err(err)?.join(
        destination
            .file_name()
            .ok_or_else(|| err("invalid destination"))?,
    );
    if target.starts_with(&source_path) {
        return Err(err("destination must be outside the source store"));
    }
    let _guard = StoreLock::acquire(source)?;
    let mut batches = Vec::new();
    let mut files = Vec::new();
    let mut directories = 0;
    for entry in fs::read_dir(source.join("data")).map_err(err)? {
        let entry = entry.map_err(err)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| err("invalid batch name"))?;
        if !entry.file_type().map_err(err)?.is_dir()
            || name.len() != 64
            || !name.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(err("unexpected entry in store data directory"));
        }
        batches.push(name);
        if batches.len() > 100_000 {
            return Err(err("compaction batch limit exceeded"));
        }
        collect_parts(&entry.path(), 0, &mut files, &mut directories)?;
    }

    batches.sort();
    files.sort();
    // create_dir is an exclusive claim: never replace a pre-existing destination.
    fs::create_dir(destination).map_err(err)?;
    let result = (|| {
        let id = identity(&[
            "compaction",
            &batches.join(":"),
            &format!("{since_ms:?}:{security_since_ms:?}"),
        ]);
        let mut writer = Writer::begin(destination, &id)?;
        let mut result = Compaction {
            read: 0,
            retained: 0,
            discarded: 0,
        };
        for path in files {
            let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path).map_err(err)?)
                .map_err(err)?
                .with_batch_size(256)
                .build()
                .map_err(err)?;
            for batch in reader {
                let batch = batch.map_err(err)?;
                let mut bytes = Vec::new();
                let mut json = LineDelimitedWriter::new(&mut bytes);
                json.write(&batch).map_err(err)?;
                json.finish().map_err(err)?;
                for line in bytes.split(|b| *b == b'\n').filter(|b| !b.is_empty()) {
                    let row: Row = serde_json::from_slice(line).map_err(err)?;
                    result.read += 1;
                    let security = ["intel.", "notice.", "anomaly.", "policy."]
                        .iter()
                        .any(|prefix| row.event_type.starts_with(prefix));
                    let cutoff = if security {
                        security_since_ms.or(since_ms)
                    } else {
                        since_ms
                    };
                    if cutoff
                        .zip(row.timestamp_ms)
                        .is_some_and(|(since, timestamp)| timestamp < since)
                    {
                        result.discarded += 1;
                    } else {
                        writer.push(row)?;
                        result.retained += 1;
                    }
                }
            }
        }
        // Empty source-batch markers preserve the repeat-import guard after compaction.
        for batch in batches {
            if batch != id {
                fs::create_dir(destination.join("data").join(batch)).map_err(err)?;
            }
        }
        writer.commit()?;
        Ok(result)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(destination);
    }
    result
}

fn collect_parts(
    path: &Path,
    depth: usize,
    files: &mut Vec<std::path::PathBuf>,
    directories: &mut usize,
) -> Result<()> {
    *directories += 1;
    if depth > 4 || *directories > 100_000 {
        return Err(err("compaction directory limit exceeded"));
    }
    for entry in fs::read_dir(path).map_err(err)? {
        let entry = entry.map_err(err)?;
        let kind = entry.file_type().map_err(err)?;
        if kind.is_dir() {
            collect_parts(&entry.path(), depth + 1, files, directories)?;
        } else if kind.is_file() && entry.path().extension().is_some_and(|e| e == "parquet") {
            files.push(entry.path());
            if files.len() > 100_000 {
                return Err(err("compaction part limit exceeded"));
            }
        } else {
            return Err(err("unexpected entry in store batch"));
        }
    }
    Ok(())
}
