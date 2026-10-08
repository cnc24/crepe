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
pub fn correlate(store: &Path, window: u64, since: Option<i64>, until: Option<i64>) -> Result<()> {
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
    let results = crepe_engine::correlation::relate(&rows, window)?;
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
    let mut result = json!({"event_id":id,"source":source,"event_chain":chain,"record":sequence,"section":section,"interface":interface,"role":role,"scope":"one referenced packet, not all bytes needed for reassembly"});
    let Some(capture) = capture else {
        result["availability"] = json!("not_checked");
        result["next_step"] =
            json!("provide --capture ORIGINAL.pcap to verify the source and locate the packet");
        return crate::history::print_json(&result);
    };
    if !capture.exists() {
        if output.is_some() {
            return Err(error("original capture is missing; cannot export evidence"));
        }
        result["availability"] = json!("missing");
        return crate::history::print_json(&result);
    }
    if crepe_storage::hash_file(capture)? != source {
        return Err(error(
            "capture hash does not match the event source; refusing unrelated evidence",
        ));
    }
    let mut found = None;
    crepe_capture::read_records(crepe_capture::open(capture)?, |record| {
        if record.header.sequence == sequence
            && u64::from(record.header.section) == section
            && u64::from(record.header.interface) == interface
        {
            found = Some((record.header, record.linktype, record.data.to_vec()));
            return Ok(false);
        }
        Ok(true)
    })?;
    let (header, linktype, data) =
        found.ok_or_else(|| error("referenced record not present in verified capture"))?;
    if crepe_storage::hash_file(capture)? != source {
        return Err(error("capture changed during evidence retrieval"));
    }
    if let Some(output) = output {
        let parent = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let stage = tempfile::tempdir_in(parent).map_err(error)?;
        let staged = stage.path().join("evidence.pcap");
        let mut export = crepe_capture::export::Export::create(&staged)?;
        export.write(&crepe_capture::Record {
            header: header.clone(),
            linktype,
            data: &data,
        })?;
        export.finish()?;
        std::fs::hard_link(&staged, output).map_err(error)?;
        result["exported_to"] = json!(output);
    }
    result["availability"] = json!("verified");
    result["header"] = serde_json::to_value(header).map_err(error)?;
    result["linktype"] = json!(linktype);
    crate::history::print_json(&result)
}
