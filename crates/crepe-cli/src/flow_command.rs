//! One bounded flow engine, with optional durable storage and historical CQL.
use crate::{
    args::{FlowArgs, Format},
    output::Output,
    packet_filter::Filter,
};
use crepe_core::{Error, Result};
use crepe_flow::{Config, FlowRecord, FlowTable};
use std::{
    io::{self, BufRead, Seek},
    path::Path,
};
fn error(e: impl std::fmt::Display) -> Error {
    Error::new("CREPE-CQL-001", e)
}
fn is_query(text: &str) -> bool {
    let without_or = text.replace("||", "");
    without_or.contains('|')
        || text.trim() == "*"
        || ["bytes", "packets", "flow.", "event.", "where "]
            .iter()
            .any(|prefix| text.trim_start().starts_with(prefix))
}
pub fn run(args: FlowArgs) -> Result<()> {
    let stored = args.file.is_dir();
    let positional_query = args.filter.as_deref().filter(|s| stored || is_query(s));
    if positional_query.is_some() && args.query.is_some() {
        return Err(error(
            "use either a positional flow query or --query, not both",
        ));
    }
    let packet_filter = if positional_query.is_some() {
        None
    } else {
        args.filter.as_deref()
    };
    let querying = stored
        || args.query.is_some()
        || positional_query.is_some()
        || args.sort.is_some()
        || args.group.is_some()
        || args.count
        || args.limit.is_some();
    if stored && args.store.is_some() {
        return Err(error(
            "--store imports a capture; omit it when reading an existing store",
        ));
    }
    let mut query = args
        .query
        .as_deref()
        .or(positional_query)
        .unwrap_or("*")
        .to_string();
    if let Some(group) = &args.group {
        query.push_str(&format!(" | group {group}"));
    }
    if args.count {
        query.push_str(" | count");
    }
    if let Some(sort) = &args.sort {
        let sort = if sort == "flows" { "count" } else { sort };
        query.push_str(&format!(" | sort {sort} desc"));
    }
    if let Some(limit) = args.limit {
        query.push_str(&format!(" | limit {limit}"));
    }
    // Validate before reading or creating a store.
    if querying {
        crepe_storage::compile(&query)?;
    }
    if stored {
        return display_query(&args.file, &query, args.format, args.details);
    }
    let mut filter = Filter::new(packet_filter, args.filter_syntax)?;
    let config = Config {
        max_flows: args.max_flows as usize,
        tcp_idle_secs: args.tcp_idle,
        udp_idle_secs: args.udp_idle,
        active_secs: args.active_timeout,
    };
    let mut table = FlowTable::new(config)?;
    let temp = tempfile::tempdir().map_err(error)?;
    let store = args
        .store
        .clone()
        .unwrap_or_else(|| temp.path().join("flows"));
    let persist = querying || args.store.is_some();
    let source = if persist {
        crepe_storage::hash_file(&args.file)?
    } else {
        String::new()
    };
    let batch = crepe_storage::identity(&[
        "flow-import",
        env!("CARGO_PKG_VERSION"),
        &source,
        packet_filter.unwrap_or(""),
        &format!("{config:?}"),
    ]);
    let mut writer = if persist {
        Some(crepe_storage::Writer::begin(&store, &batch)?)
    } else {
        None
    };
    let mut out = Output::new(io::BufWriter::new(io::stdout().lock()), args.format);
    if !querying && (!args.details || !matches!(args.format, Format::Table)) {
        out.header(true)?;
    }
    let mut emit = |flow: FlowRecord| {
        if let Some(writer) = &mut writer {
            writer.push(crepe_engine::flow_row("local", &source, flow.clone())?)?;
        }
        if !querying {
            out.flow(&flow, args.details)?;
        }
        Ok(())
    };
    crepe_capture::read_records(crepe_capture::open(&args.file)?, |record| {
        if !filter.raw_matches(&record)? {
            return Ok(true);
        }
        if let Some(view) =
            crepe_packet::decode_view(record.data, record.header.clone(), record.linktype)?
        {
            if filter.view_matches(&view) {
                table.push(&view.event, &mut emit)?;
            }
        }
        Ok(true)
    })?;
    table.finish(&mut emit)?;
    if table.skipped_fragments != 0 || table.skipped_other_protocols != 0 {
        crate::report!(
            "Skipped {} fragmented and {} non-TCP/UDP packets for flow accounting.",
            table.skipped_fragments,
            table.skipped_other_protocols
        );
    }
    out.flush()?;
    // Release stdout before query output acquires its own lock.
    drop(out);
    if let Some(writer) = writer {
        if crepe_storage::hash_file(&args.file)? != source {
            return Err(error("input changed during flow import; batch discarded"));
        }
        let count = writer.commit()?;
        if args.store.is_some() {
            crate::report!("Saved {count} flows to {}. Query with: crepe query STORE '* | sort bytes desc | limit 10' (replace STORE with this path).",store.display());
        }
    }
    if querying {
        display_query(&store, &query, args.format, args.details)?;
    }
    Ok(())
}
fn display_query(store: &Path, query: &str, format: Format, details: bool) -> Result<()> {
    // A store may also contain packet/application rows. Scope BEFORE aggregation.
    let mut quoted = false;
    let bytes = query.as_bytes();
    let first_pipe = bytes.iter().enumerate().find_map(|(i, &byte)| {
        if byte == b'"' {
            quoted = !quoted;
        }
        (byte == b'|'
            && !quoted
            && bytes.get(i.wrapping_sub(1)) != Some(&b'|')
            && bytes.get(i + 1) != Some(&b'|'))
        .then_some(i)
    });
    let (predicate, pipeline) = first_pipe
        .map(|i| (&query[..i], &query[i..]))
        .unwrap_or((query, ""));
    let predicate = predicate
        .trim()
        .strip_prefix("where ")
        .unwrap_or(predicate.trim());
    let scoped = if predicate.is_empty() || predicate == "*" {
        format!("event.type == flow.end {pipeline}")
    } else {
        format!("event.type == flow.end && ({predicate}) {pipeline}")
    };
    let mut result = tempfile::tempfile().map_err(error)?;
    crepe_storage::query(store, &scoped, &mut result)?;
    result.rewind().map_err(error)?;
    let mut out = Output::new(io::BufWriter::new(io::stdout().lock()), format);
    let mut header = false;
    for line in io::BufReader::new(result).lines() {
        let line = line.map_err(error)?;
        let row: serde_json::Value = serde_json::from_str(&line).map_err(error)?;
        if matches!(format, Format::Json) {
            out.query_value(&row)?;
            continue;
        }
        if let Some(flow) = row["payload"]
            .as_str()
            .and_then(|s| serde_json::from_str::<FlowRecord>(s).ok())
        {
            if !header {
                if !details || matches!(format, Format::Csv) {
                    out.header(true)?;
                }
                header = true;
            }
            out.flow(&flow, details)?;
        } else {
            out.query_columns(&row, !header)?;
            header = true;
        }
    }
    out.flush()
}
