//! Read-only correlation and explicit, hash-checked packet evidence retrieval.
use crepe_core::{Error, Result};
use serde_json::{json, Value};
use std::{
    io::{BufRead, Seek},
    path::Path,
};
fn error(message: impl std::fmt::Display) -> Error {
    Error::new("CREPE-EVIDENCE-001", message)
}
fn query(store: &Path, expression: &str) -> Result<Vec<Value>> {
    let mut file = tempfile::tempfile().map_err(error)?;
    crepe_storage::query(store, expression, &mut file)?;
    file.rewind().map_err(error)?;
    let mut total = 0;
    let mut rows = Vec::new();
    for line in std::io::BufReader::new(file).lines() {
        let line = line.map_err(error)?;
        total += line.len();
        if total > 16 * 1024 * 1024 {
            return Err(error(
                "investigation selection exceeds 16 MiB; narrow the time interval",
            ));
        }
        rows.push(serde_json::from_str(&line).map_err(error)?);
    }
    Ok(rows)
}
pub fn correlate(
    store: &Path,
    window: u64,
    since: Option<i64>,
    until: Option<i64>,
    cross_source: bool,
) -> Result<()> {
    if crepe_storage::schema_version(store)? != 2 {
        return Err(error("correlation requires schema-2 instance identities; reimport original captures into a NEW store"));
    }
    if since.zip(until).is_some_and(|(a, b)| a > b) {
        return Err(error("--since-ms must not exceed --until-ms"));
    }
    let mut expression = "(event.type == dns.response || event.type == tls.client_hello || event.type == intel.match)".to_string();
    if let Some(since) = since {
        expression.push_str(&format!(" && timestamp >= {since}"));
    }
    if let Some(until) = until {
        expression.push_str(&format!(" && timestamp <= {until}"));
    }
    expression.push_str(" | sort timestamp asc");
    let rows = query(store, &expression)?;
    if rows.len() >= 10000 {
        return Err(error("selection reaches the 10000-row limit; narrow --since-ms/--until-ms to avoid incomplete correlations"));
    }
    let rows = rows
        .into_iter()
        .map(serde_json::from_value)
        .collect::<std::result::Result<Vec<crepe_storage::Row>, _>>()
        .map_err(error)?;
    let results = crepe_engine::correlation::relate_sources(&rows, window, cross_source)?;
    for result in &results {
        crate::history::print_json(result)?;
    }
    crate::report!("Examined {} stored observations; {} DNS/TLS relationship results. Relations are inferred, not proof of causality.",rows.len(),results.len());
    Ok(())
}
fn valid_id(id: &str) -> Result<()> {
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(error("expected a 64-character hexadecimal event_id"));
    }
    Ok(())
}
fn event(store: &Path, id: &str) -> Result<Value> {
    valid_id(id)?;
    let rows = query(store, &format!("event.id == {id} | limit 2"))?;
    if rows.len() != 1 {
        return Err(error("event_id is missing or ambiguous in this store"));
    }
    Ok(rows.into_iter().next().unwrap())
}
pub fn evidence(
    store: &Path,
    id: &str,
    capture: Option<&Path>,
    output: Option<&Path>,
) -> Result<()> {
    let mut row = event(store, id)?;
    let source = row["source"]
        .as_str()
        .ok_or_else(|| error("event has no source identity"))?
        .to_string();
    let sensor = row["sensor"].clone();
    let mut chain = Vec::new();
    let mut reference = None;
    let mut provenance: Option<crepe_core::PacketEvidence> = None;
    for _ in 0..8 {
        let current = row["event_id"]
            .as_str()
            .ok_or_else(|| error("missing event identity"))?
            .to_string();
        if chain.contains(&current) {
            return Err(error("cyclic evidence reference"));
        }
        chain.push(current);
        let payload: Value = serde_json::from_str(
            row["payload"]
                .as_str()
                .ok_or_else(|| error("missing event payload"))?,
        )
        .map_err(error)?;
        if let Some(value) = payload.get("evidence") {
            let evidence: crepe_core::PacketEvidence =
                serde_json::from_value(value.clone()).map_err(error)?;
            if !evidence.records.is_empty() && evidence.records.len() <= 4096 {
                let first = evidence.records[0];
                reference = Some((
                    first.sequence,
                    u64::from(first.section),
                    u64::from(first.interface),
                    "analysis_input_packets",
                ));
                provenance = Some(evidence);
                break;
            }
        }
        let header = payload
            .get("header")
            .or_else(|| payload.pointer("/packet/header"));
        if let Some(header) = header {
            if let (Some(sequence), Some(section), Some(interface)) = (
                header["sequence"].as_u64(),
                header["section"].as_u64(),
                header["interface"].as_u64(),
            ) {
                reference = Some((sequence, section, interface, "referenced_packet"));
                break;
            }
        }
        if row["event_type"] == "flow.end" {
            if let (Some(sequence), Some(section), Some(interface)) = (
                payload["first_sequence"].as_u64().filter(|n| *n > 0),
                payload["section"].as_u64(),
                payload["interface"].as_u64(),
            ) {
                reference = Some((sequence, section, interface, "first_observed_packet"));
                break;
            }
        }
        let Some(parent) = payload["source_event_id"].as_str() else {
            break;
        };
        row = event(store, parent)?;
        if row["source"] != source || row["sensor"] != sensor {
            return Err(error("evidence parent crosses source/sensor boundaries"));
        }
    }
    let Some((sequence, section, interface, role)) = reference else {
        if output.is_some() {
            return Err(error("event has no retrievable packet reference"));
        }
        return crate::history::print_json(
            &json!({"event_id":id,"availability":"unavailable","reason":"no packet reference (exported telemetry, legacy flow, or exhausted reference chain)","source":source,"event_chain":chain}),
        );
    };
    let fallback = crepe_core::PacketRef {
        sequence,
        section: u32::try_from(section).map_err(error)?,
        interface: u32::try_from(interface).map_err(error)?,
    };
    let references = provenance
        .as_ref()
        .map(|p| p.records.clone())
        .unwrap_or_else(|| vec![fallback]);
    let mut result = json!({"event_id":id,"source":source,"event_chain":chain,"record":sequence,"section":section,"interface":interface,"role":role,
        "scope":provenance.as_ref().map(|p|p.scope.as_str()).unwrap_or("one referenced packet; legacy events have no complete reassembly provenance"),
        "provenance_complete":provenance.as_ref().is_some_and(|p|p.complete),"references":references});
    // Group references by original/retained file; scan each source only once.
    let mut files: std::collections::BTreeMap<
        std::path::PathBuf,
        (String, Vec<(u64, crepe_core::PacketRef)>),
    > = Default::default();
    for reference in &references {
        let located = match capture {
            Some(path) => Some((path.to_path_buf(), source.clone(), reference.sequence)),
            None => crepe_engine::raw::locate(store, &source, *reference)?,
        };
        let Some((path, hash, local_sequence)) = located else {
            if output.is_some() {
                return Err(error(
                    "raw evidence not retained or expired; provide --capture ORIGINAL.pcap",
                ));
            }
            result["availability"] = json!("unavailable");
            result["reason"] =
                json!("raw evidence not retained or expired; provide --capture ORIGINAL.pcap");
            return crate::history::print_json(&result);
        };
        files
            .entry(path)
            .or_insert_with(|| (hash, Vec::new()))
            .1
            .push((local_sequence, *reference));
    }
    let parent = output
        .and_then(Path::parent)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let stage = output
        .map(|_| tempfile::tempdir_in(parent).map_err(error))
        .transpose()?;
    let staged = stage.as_ref().map(|s| s.path().join("evidence.pcap"));
    let mut export = staged
        .as_ref()
        .map(|p| crepe_capture::export::Export::create(p))
        .transpose()?;
    let mut files: Vec<_> = files.into_iter().collect();
    files.sort_by_key(|(_, (_, refs))| refs.iter().map(|(_, r)| r.sequence).min());
    let mut found = Vec::new();
    for (path, (hash, refs)) in files {
        if !path.exists() {
            if output.is_some() {
                return Err(error("original capture is missing; cannot export evidence"));
            }
            result["availability"] = json!("missing");
            return crate::history::print_json(&result);
        }
        if crepe_storage::hash_file(&path)? != hash {
            return Err(error(
                "capture hash does not match the event source; refusing unrelated evidence",
            ));
        }
        let expected: std::collections::BTreeMap<_, _> = refs.into_iter().collect();
        let mut remaining = expected.len();
        crepe_capture::read_records(crepe_capture::open(&path)?, |record| {
            if let Some(reference) = expected.get(&record.header.sequence) {
                if capture.is_some()
                    && (record.header.section != reference.section
                        || record.header.interface != reference.interface)
                {
                    return Err(error("packet context differs from evidence reference"));
                }
                if let Some(export) = &mut export {
                    export.write(&record)?;
                }
                found.push(json!({"reference":reference,"header":record.header,"linktype":record.linktype}));
                remaining -= 1;
            }
            Ok(remaining > 0)
        })?;
        if remaining != 0 {
            return Err(error("referenced record not present in verified capture"));
        }
        if crepe_storage::hash_file(&path)? != hash {
            return Err(error("capture changed during evidence retrieval"));
        }
    }
    if let Some(export) = export {
        export.finish()?;
        std::fs::hard_link(staged.as_ref().unwrap(), output.unwrap()).map_err(error)?;
        result["exported_to"] = json!(output);
    }
    result["availability"] = json!("verified");
    result["header"] = found[0]["header"].clone();
    result["linktype"] = found[0]["linktype"].clone();
    result["packets"] = json!(found);
    crate::history::print_json(&result)
}

pub fn related_timeline(store: &Path, id: &str, limit: u32) -> Result<()> {
    let focus = event(store, id)?;
    let at = focus["timestamp_ms"]
        .as_i64()
        .ok_or_else(|| error("focused timeline requires an observed timestamp"))?;
    let filter=format!("(type == dns.response || type == tls.client_hello || type == intel.match) && timestamp >= {} && timestamp <= {} | sort timestamp",at.saturating_sub(300000),at.saturating_add(300000));
    let selection = query(store, &filter)?;
    if selection.len() >= 10000 {
        return Err(error(
            "related-event window reaches row limit; use narrower correlate time bounds",
        ));
    }
    let rows = selection
        .into_iter()
        .map(serde_json::from_value)
        .collect::<std::result::Result<Vec<crepe_storage::Row>, _>>()
        .map_err(error)?;
    let relations = crepe_engine::correlation::relate(&rows, 300)?;
    let initial = focus["flow_id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error("event has no flow-instance reference"))?;
    let mut flows = std::collections::BTreeSet::from([initial.to_string()]);
    let relations: Vec<_> = relations
        .into_iter()
        .filter(|r| r["tls_flow_id"] == initial || r["dns_flow_id"] == initial)
        .collect();
    for relation in &relations {
        for key in ["dns_flow_id", "tls_flow_id"] {
            if let Some(flow) = relation[key].as_str() {
                valid_id(flow)?;
                flows.insert(flow.into());
            }
        }
    }
    let predicates = flows
        .iter()
        .map(|id| format!("flow.id == {id}"))
        .collect::<Vec<_>>()
        .join(" || ");
    if predicates.len() > 15000 {
        return Err(error("too many related flows; narrow the investigation"));
    }
    let mut observations = query(store, &format!("({predicates}) | sort timestamp"))?;
    let truncated = observations.len() >= 10000 || observations.len() > limit as usize;
    observations.truncate(limit as usize);
    crate::history::print_json(
        &json!({"event_type":"investigation.timeline","focus_event_id":id,"relations":relations,"observations":observations,"truncated":truncated,"window_seconds":300,"clock_alignment":"unverified"}),
    )
}
