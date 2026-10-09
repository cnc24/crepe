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
    if text.trim() == "*" {
        return true;
    }
    // Inspect identifiers outside quoted literals, regardless of parentheses/negation.
    let mut quoted = false;
    let mut visible = String::with_capacity(text.len());
    for c in text.chars() {
        if c == '"' {
            quoted = !quoted;
            visible.push(' ');
        } else {
            visible.push(if quoted { ' ' } else { c });
        }
    }
    visible.replace("||", "").contains('|')
        || visible
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '_')
            .any(|word| {
                matches!(word, "bytes" | "packets" | "where")
                    || word.starts_with("flow.")
                    || word.starts_with("event.")
                    || word.starts_with("conversation.")
                    || word.starts_with("identity.")
            })
}
pub fn run(args: FlowArgs) -> Result<()> {
    let stored = args.file.is_dir();
    if stored
        && (args.filter_syntax.is_some()
            || args.max_flows.is_some()
            || args.tcp_idle.is_some()
            || args.udp_idle.is_some()
            || args.active_timeout.is_some())
    {
        return Err(error("packet-filter syntax and flow timeouts/capacity apply only to capture input, not an existing store; use a historical CQL query"));
    }
    let positional_query = args.filter.as_deref().filter(|s| {
        stored
            || (!matches!(args.filter_syntax, Some(crate::args::FilterSyntax::Bpf)) && is_query(s))
    });
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
        let sorted = format!("{query} | sort {sort} desc");
        if sort == "count" && crepe_storage::compile(&sorted).is_err() {
            return Err(error("--sort flows/count needs a count result: use --group src.ip (or a CQL group/count pipeline), then sort"));
        }
        query = sorted;
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
    let mut filter = Filter::new(
        packet_filter,
        args.filter_syntax
            .unwrap_or(crate::args::FilterSyntax::Auto),
    )?;
    let config = Config {
        max_flows: args.max_flows.unwrap_or(65536) as usize,
        tcp_idle_secs: args.tcp_idle.unwrap_or(120),
        udp_idle_secs: args.udp_idle.unwrap_or(30),
        active_secs: args.active_timeout.unwrap_or(300),
    };
    let mut table = FlowTable::new(config)?;
    let persist = querying || args.store.is_some();
    let temp = if persist && args.store.is_none() {
        Some(tempfile::tempdir().map_err(error)?)
    } else {
        None
    };
    let store = args
        .store
        .clone()
        .or_else(|| temp.as_ref().map(|t| t.path().join("flows")));
    if persist {
        crate::report!(
            "Preparing flow import from {} (hashing source)...",
            args.file.display()
        );
    }
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
        Some(crepe_storage::Writer::begin(
            store.as_ref().expect("persistent destination"),
            &batch,
        )?)
    } else {
        None
    };
    let mut out = Output::new(io::BufWriter::new(io::stdout().lock()), args.format);
    let mut output_closed = false;
    if !querying && (!args.details || !matches!(args.format, Format::Table)) {
        if let Err(e) = out.header(true) {
            if persist && e.code == "CREPE-IO-PIPE" {
                output_closed = true;
            } else {
                return Err(e);
            }
        }
    }
    let mut emit = |flow: FlowRecord| {
        if let Some(writer) = &mut writer {
            writer.push(crepe_engine::flow_row("local", &source, flow.clone())?)?;
        }
        if !querying && !output_closed {
            if let Err(e) = out.flow(&flow, args.details) {
                if persist && e.code == "CREPE-IO-PIPE" {
                    output_closed = true;
                } else {
                    return Err(e);
                }
            }
        }
        Ok(())
    };
    let mut records = 0_u64;
    let mut progress = std::time::Instant::now();
    if persist {
        crate::report!(
            "Aggregating flows; results are committed after the complete capture is processed."
        );
    }
    crepe_capture::read_records(crepe_capture::open(&args.file)?, |record| {
        records += 1;
        if persist && progress.elapsed().as_secs() >= 2 {
            crate::report!("Flow import: processed {records} capture records.");
            progress = std::time::Instant::now();
        }
        if !filter.raw_matches(&record)? {
            return Ok(true);
        }
        if let Some(view) =
            crepe_packet::decode_view(record.data, record.header.clone(), record.linktype)?
        {
            if filter.view_matches(&view) {
                table.push_with_sequence(&view.event, view.tcp_sequence, &mut emit)?;
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
    if let Err(e) = out.flush() {
        if !(persist && e.code == "CREPE-IO-PIPE") {
            return Err(e);
        }
    }
    // Release stdout before query output acquires its own lock.
    drop(out);
    if let Some(writer) = writer {
        crate::report!(
            "Verifying source and committing flow history ({records} records processed)..."
        );
        if crepe_storage::hash_file(&args.file)? != source {
            return Err(error("input changed during flow import; batch discarded"));
        }
        let count = writer.commit()?;
        if args.store.is_some() {
            crate::report!("Saved {count} flows to {}. Query with: crepe query STORE '* | sort bytes desc | limit 10' (replace STORE with this path).",store.as_ref().expect("persistent destination").display());
        }
    }
    if querying {
        display_query(
            store.as_ref().expect("query destination"),
            &query,
            args.format,
            args.details,
        )?;
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
