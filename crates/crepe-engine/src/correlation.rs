//! Conservative, bounded DNS-answer → TLS-SNI evidence relationships.
//! These are inferred relationships, never claims of causality or decryption.
use crepe_core::{Error, Result};
use crepe_storage::Row;
use serde_json::{json, Value};
use std::{collections::BTreeMap, net::IpAddr};
fn error(message: &str) -> Error {
    Error::new("CREPE-CORRELATE-001", message)
}
fn name(value: &str) -> String {
    value.trim_end_matches('.').to_ascii_lowercase()
}
fn time(row: &Row) -> Option<i128> {
    row.timestamp_ns.as_deref()?.parse().ok()
}
fn context(payload: &Value) -> Option<String> {
    let packet = payload.get("packet")?;
    Some(
        json!([
            packet.pointer("/header/section")?.as_u64()?,
            packet.pointer("/header/interface")?.as_u64()?,
            packet.get("vlans")?.as_array()?
        ])
        .to_string(),
    )
}
struct Binding<'a> {
    row: &'a Row,
    name: String,
    address: IpAddr,
    at: i128,
    ttl: u64,
    context: String,
}
/// Accept a complete bounded observation selection. Caller must not silently truncate.
pub fn relate(rows: &[Row], window_seconds: u64) -> Result<Vec<Value>> {
    if rows.len() >= 10000 || !(1..=3600).contains(&window_seconds) {
        return Err(error(
            "select fewer than 10000 observations and a window of 1..3600 seconds",
        ));
    }
    if rows
        .iter()
        .try_fold(0_usize, |n, r| n.checked_add(r.payload.len()))
        .is_none_or(|n| n > 16 * 1024 * 1024)
    {
        return Err(error("correlation payload budget exceeds 16 MiB"));
    }
    let mut bindings = Vec::new();
    let mut intel: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for row in rows {
        let payload: Value = serde_json::from_str(&row.payload)
            .map_err(|_| error("invalid stored event payload"))?;
        if row.event_type == "intel.match" {
            if let Some(parent) = payload["source_event_id"].as_str() {
                intel.entry(parent.into()).or_default().push(&row.event_id);
            }
        }
        if row.event_type != "dns.response"
            || row.flow_id.is_empty()
            || row.identity_status != "instance"
        {
            continue;
        }
        let Some(at) = time(row) else {
            continue;
        };
        let Some(context) = context(&payload) else {
            continue;
        };
        let dns = &payload["dns"];
        if dns["rcode"] != 0 || dns["truncated"] != false || dns["response"] != true {
            continue;
        }
        for answer in dns["answers"].as_array().into_iter().flatten() {
            if answer["class"] != 1
                || !matches!(answer["data"]["type"].as_str(), Some("a" | "aaaa"))
            {
                continue;
            }
            let Some(owner) = answer["name"].as_str() else {
                continue;
            };
            let owner = name(owner);
            let queried =
                dns["questions"].as_array().into_iter().flatten().any(|q| {
                    q["class"] == 1 && q["name"].as_str().is_some_and(|n| name(n) == owner)
                });
            if !queried {
                continue;
            }
            let Some(address) = answer["data"]["value"]
                .as_str()
                .and_then(|s| s.parse().ok())
            else {
                continue;
            };
            let Some(ttl) = answer["ttl"]
                .as_u64()
                .filter(|t| *t > 0 && *t <= u64::from(u32::MAX))
            else {
                continue;
            };
            if bindings.len() >= 10000 {
                return Err(error(
                    "DNS answer budget exceeded; narrow the selected time interval",
                ));
            }
            bindings.push(Binding {
                row,
                name: owner,
                address,
                at,
                ttl,
                context: context.clone(),
            });
        }
    }
    let mut output = Vec::new();
    for tls in rows.iter().filter(|r| r.event_type == "tls.client_hello") {
        let payload: Value =
            serde_json::from_str(&tls.payload).map_err(|_| error("invalid TLS payload"))?;
        let sni = payload
            .pointer("/protocol/server_name")
            .and_then(Value::as_str)
            .map(name);
        let at = time(tls);
        let network = context(&payload);
        let address = tls.dst_ip.as_deref().and_then(|s| s.parse::<IpAddr>().ok());
        let mut candidates = Vec::new();
        if let (Some(sni), Some(at), Some(network), Some(address), Some(client)) =
            (&sni, at, &network, address, &tls.src_ip)
        {
            for dns in &bindings {
                let Some(delta) = at.checked_sub(dns.at) else {
                    continue;
                };
                if dns.name == *sni
                    && dns.address == address
                    && dns.row.sensor == tls.sensor
                    && dns.row.source == tls.source
                    && dns.context == *network
                    && dns.row.dst_ip.as_ref() == Some(client)
                    && tls.identity_status == "instance"
                    && !tls.flow_id.is_empty()
                    && dns.row.flow_id != tls.flow_id
                    && delta >= 0
                    && delta <= i128::from(window_seconds) * 1_000_000_000
                    && delta < i128::from(dns.ttl) * 1_000_000_000
                {
                    candidates.push((dns, delta));
                }
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        candidates.retain(|(dns, _)| seen.insert(dns.row.event_id.clone()));
        if candidates.is_empty() {
            output.push(json!({"event_type":"correlation.dns_tls", "status":"unmatched", "tls_event_id":tls.event_id,
                "tls_flow_id":tls.flow_id,"server_name":sni,"reason":"no direct DNS answer satisfying source, sensor, client, link context, destination IP, SNI, TTL and time window",
                "limits":"missing timestamps/SNI/instance identity, ECH, CNAME-only answers and other capture sources are not inferred"}));
        } else {
            for (dns, delta) in &candidates {
                let related_intel: Vec<_> = intel
                    .get(&tls.event_id)
                    .into_iter()
                    .flatten()
                    .chain(intel.get(&dns.row.event_id).into_iter().flatten())
                    .copied()
                    .collect();
                output.push(json!({"event_type":"correlation.dns_tls", "status":if candidates.len()>1 {"ambiguous"} else {"inferred"},
                    "candidate_count":candidates.len(),"dns_event_id":dns.row.event_id,"dns_flow_id":dns.row.flow_id,"tls_event_id":tls.event_id,"tls_flow_id":tls.flow_id,
                    "sensor":tls.sensor,"source":tls.source,"client":tls.src_ip,"server_name":sni,"destination_ip":tls.dst_ip,
                    "delta_ns":delta.to_string(),"dns_ttl_seconds":dns.ttl,"window_seconds":window_seconds,"intel_event_ids":related_intel,
                    "basis":["same sensor/source/link context","DNS response delivered to TLS client","direct A/AAAA answer matches TLS destination","answer owner matches visible SNI","DNS precedes TLS within TTL and window"],
                    "uncertainty":"observational association, not proof that this DNS answer caused the connection; capture-clock accuracy is not established"}));
            }
        }
        if output.len() > 10000 {
            return Err(error(
                "correlation result budget exceeded; narrow the selected time interval",
            ));
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pair() -> Vec<Row> {
        let packet = json!({"header":{"section":0,"interface":0},"vlans":[]});
        vec![Row { event_id:"dns".into(), identity_status:"instance".into(), flow_id:"dns-flow".into(), sensor:"lab".into(),source:"capture".into(),
            timestamp_ns:Some("1000000000".into()),event_type:"dns.response".into(),dst_ip:Some("192.0.2.10".into()),
            payload:json!({"packet":packet,"dns":{"rcode":0,"truncated":false,"response":true,"questions":[{"name":"Example.Test.","class":1}],"answers":[{"name":"example.test.","class":1,"ttl":60,"data":{"type":"a","value":"198.51.100.20"}}]}}).to_string(),..Default::default()},
            Row { event_id:"tls".into(),identity_status:"instance".into(),flow_id:"tls-flow".into(),sensor:"lab".into(),source:"capture".into(),timestamp_ns:Some("2000000000".into()),
                event_type:"tls.client_hello".into(),src_ip:Some("192.0.2.10".into()),dst_ip:Some("198.51.100.20".into()),
                payload:json!({"packet":packet,"protocol":{"server_name":"EXAMPLE.TEST"}}).to_string(),..Default::default()}]
    }
    #[test]
    fn ttl_context_and_identity_are_required_and_ambiguity_is_explicit() {
        let rows = pair();
        assert_eq!(relate(&rows, 300).unwrap()[0]["status"], "inferred");
        for change in 0..10 {
            let mut rows = pair();
            match change {
                0 => rows[1].timestamp_ns = Some("61000000000".into()), // TTL boundary is expired.
                1 => rows[1].timestamp_ns = Some("0".into()),
                2 => rows[1].src_ip = Some("192.0.2.11".into()),
                3 => rows[1].source = "another-capture".into(),
                4 => rows[1].sensor = "another-sensor".into(),
                5 => rows[1].flow_id.clear(),
                6 => rows[1].dst_ip = Some("203.0.113.1".into()),
                7 => rows[0].identity_status.clear(),
                8 => rows[1].identity_status.clear(),
                _ => rows[1].timestamp_ns = None,
            }
            assert_eq!(
                relate(&rows, 300).unwrap()[0]["status"],
                "unmatched",
                "case {change}"
            );
        }
        let mut rows = pair();
        let mut duplicate = rows[0].clone();
        duplicate.event_id = "dns-other".into();
        rows.push(duplicate);
        let results = relate(&rows, 300).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results
            .iter()
            .all(|r| r["status"] == "ambiguous" && r["candidate_count"] == 2));
        let mut rows = pair();
        rows.push(Row {
            event_id: "intel".into(),
            event_type: "intel.match".into(),
            payload: json!({"source_event_id":"tls"}).to_string(),
            ..Default::default()
        });
        assert_eq!(
            relate(&rows, 300).unwrap()[0]["intel_event_ids"],
            json!(["intel"])
        );
    }
    #[test]
    fn missing_sni_truncated_answers_and_network_context_are_not_guessed() {
        for change in 0..5 {
            let mut rows = pair();
            let which = if change < 2 { 1 } else { 0 };
            let mut payload: Value = serde_json::from_str(&rows[which].payload).unwrap();
            match change {
                0 => payload["protocol"]["server_name"] = Value::Null,
                1 => payload["packet"]["header"]["interface"] = json!(2),
                2 => payload["dns"]["truncated"] = json!(true),
                3 => payload["dns"]["answers"][0]["ttl"] = json!(0),
                _ => payload["dns"]["questions"][0]["name"] = json!("unrelated.test"),
            }
            rows[which].payload = payload.to_string();
            assert_eq!(relate(&rows, 300).unwrap()[0]["status"], "unmatched");
        }
        let mut rows = pair();
        rows[1].timestamp_ns = Some("3000000001".into());
        assert_eq!(relate(&rows, 2).unwrap()[0]["status"], "unmatched");
        assert!(relate(&vec![Row::default(); 10000], 300).is_err());
    }
}
