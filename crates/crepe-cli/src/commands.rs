#[cfg(feature = "live")]
use crate::live;
use crate::packet_filter::Filter;
use crate::{
    args::{Cli, Command, PacketArgs},
    output,
};
use crepe_capture::{self as capture, export::Export};
use crepe_core::Result;
use std::io;

fn packets(
    args: PacketArgs,
    live: bool,
    source: impl FnOnce(&mut dyn FnMut(capture::Record<'_>) -> Result<bool>) -> Result<()>,
) -> Result<()> {
    if (args.ascii || args.hex > 0 || args.verbose > 0)
        && !matches!(args.format, crate::Format::Table)
    {
        return Err(crepe_core::Error::new(
            "CREPE-CLI-001",
            "--ascii/--hex require table output",
        ));
    }
    let mut filter = Filter::new(args.filter.as_deref(), args.filter_syntax)?;
    let mut export = args.write.as_deref().map(Export::create).transpose()?;
    let mut out = output::Output::new(io::BufWriter::new(io::stdout().lock()), args.format);
    out.header(false)?;
    let mut matched = 0;
    let mut malformed = 0_u64;
    let result = source(&mut |record| {
        if !filter.raw_matches(&record)? {
            return Ok(true);
        }
        if let Some(link) = match crate::link_display::decode(&record) {
            Ok(value) => value,
            Err(error) if args.tolerant => {
                malformed += 1;
                let _ = error;
                return Ok(true);
            }
            Err(error) => return Err(error),
        } {
            if filter.link_matches(link.proto) {
                if let Some(export) = &mut export {
                    export.write(&record)?;
                }
                out.link(&link)?;
                out.payload(
                    if args.hex > 1 {
                        record.data
                    } else {
                        link.payload
                    },
                    args.ascii,
                    args.hex > 0,
                )?;
                if live {
                    out.flush()?;
                }
                matched += 1;
                return Ok(args.limit.is_none_or(|limit| matched < limit));
            }
            return Ok(true);
        }
        let decoded =
            match crepe_packet::decode_view(record.data, record.header.clone(), record.linktype) {
                Ok(value) => value,
                Err(error) if args.tolerant && error.code == "CREPE-PKT-001" => {
                    malformed += 1;
                    return Ok(true);
                }
                Err(error) => {
                    return Err(crepe_core::Error::new(
                        error.code,
                        format!("record {}: {}", record.header.sequence, error.message),
                    ))
                }
            };
        let Some(view) = decoded else {
            return Ok(true);
        };
        if !filter.view_matches(&view) {
            return Ok(true);
        }
        if let Some(export) = &mut export {
            export.write(&record)?;
        }
        out.packet(&view)?;
        if args.verbose > 0 {
            out.packet_details(&record, &view, args.verbose)?;
        }
        if args.ascii || args.hex > 0 {
            let bytes = if args.hex > 1 {
                record.data
            } else {
                crepe_packet::network(record.data, record.linktype)?
                    .map(|(ip, _)| ip)
                    .unwrap_or(view.payload)
            };
            out.payload(bytes, args.ascii, args.hex > 0)?;
        }
        if live {
            out.flush()?;
        }
        matched += 1;
        Ok(args.limit.is_none_or(|limit| matched < limit))
    });
    // Flush partial output even on an input error, while preserving the original failure.
    let output_result = out.flush();
    let export_result = export.map(Export::finish).transpose();
    if malformed > 0 {
        crate::report!("Oh là là! [CREPE-PKT-001] Skipped {malformed} malformed packet payloads.");
    }
    result?;
    output_result?;
    export_result?;
    Ok(())
}
pub(crate) fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Licenses => {
            use std::io::Write;
            let mut out = io::stdout().lock();
            out.write_all(include_bytes!("../../../LICENSE"))
                .map_err(crate::output_error)?;
            out.write_all(b"\n\n").map_err(crate::output_error)?;
            out.write_all(include_bytes!("../../../THIRD-PARTY-NOTICES.txt"))
                .map_err(crate::output_error)
        }
        Command::Update { check, output } => crate::update::run(check, output.as_deref()),
        Command::Daemon { config, duration } => {
            let settings = crate::history::config(Some(&config))?;
            if settings.interface.is_none() || settings.store.is_none() {
                return Err(crepe_core::Error::new(
                    "CREPE-CONFIG-001",
                    "daemon requires interface and store in its configuration",
                ));
            }
            crate::recipes::run(
                crepe_engine::Profile::Maison,
                crate::args::RecipeArgs {
                    file: None,
                    interface: settings.interface,
                    duration,
                    store: settings.store,
                    config: Some(config),
                    enable: Vec::new(),
                    disable: Vec::new(),
                    tolerant: false,
                    listen: settings.collector_listen,
                    query: None,
                    query_interval: 5,
                    workers: None,
                },
            )
        }
        Command::Chocolate(args) => crate::recipes::run(crepe_engine::Profile::Chocolate, args),
        Command::Suzette(args) => crate::recipes::run(crepe_engine::Profile::Suzette, args),
        Command::Maison(args) => crate::recipes::run(crepe_engine::Profile::Maison, args),
        Command::Complete(args) => crate::recipes::run(crepe_engine::Profile::Complete, args),
        Command::Ingest {
            file,
            store,
            config,
            sensor,
            profile,
        } => {
            let mut c = crate::history::config(config.as_deref())?;
            if let Some(sensor) = sensor {
                c.sensor = sensor;
            }
            if let Some(profile) = profile {
                c.profile = profile.into();
            }
            let summary = crepe_engine::ingest(&file, &store, &c)?;
            crate::history::print_json(&summary)
        }
        Command::Logo => {
            use std::io::Write;
            io::stdout()
                .lock()
                .write_all(crate::help::LOGO.as_bytes())
                .map_err(crate::output_error)
        }
        Command::Profiles => crate::history::print_json(&serde_json::json!({
            "greeting": if crate::reporting::flair_enabled() { "Bon appétit! Choose an analysis workflow." } else { "Choose an analysis workflow." },
            "profiles": {
                "sucre": "Packet metadata",
                "chocolate": "Deep network analysis: packets, flows, DNS/TLS/HTTP/SSH, anomalies and notices",
                "banane": "NetFlow v5/v9 and IPFIX UDP collector",
                "suzette": "Persistent forensic case by default, historical queries, statistics, timeline and trace",
                "maison": "Your own configuration via --config FILE",
                "complete": "All implemented packet-analysis engines; add --listen for NetFlow/IPFIX input"
            }
        })),
        Command::Config { file } => {
            crate::history::print_json(&crate::history::config(file.as_deref())?)
        }
        Command::Query { store, cql } => crate::history::query(&store, &cql),
        Command::Compact {
            store,
            output,
            since_ms,
        } => crate::history::print_json(&crepe_storage::compact(&store, &output, since_ms)?),
        Command::Trace { store, flow_id } => {
            if flow_id.len() != 64 || !flow_id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(crepe_core::Error::new(
                    "CREPE-CQL-001",
                    "flow ID must be a 64-character hex identity",
                ));
            }
            crate::history::query(&store, &format!("flow.id == {flow_id} | sort timestamp"))
        }
        Command::Timeline { store, limit } => {
            crate::history::query(&store, &format!("* | sort timestamp | limit {limit}"))
        }
        Command::Collect {
            listen,
            duration,
            count,
            store,
            sensor,
        } => crate::history::collect(listen, duration, count, store.as_deref(), &sensor),
        Command::Analyze {
            file,
            format,
            dns_port,
            max_streams,
            max_buffer_bytes,
            stream_idle,
        } => {
            let mut analyzer = crepe_analysis::Processor::new(crepe_analysis::Config {
                dns_ports: vec![dns_port],
                max_streams: max_streams as usize,
                max_buffer_bytes: max_buffer_bytes as usize,
                idle_secs: stream_idle,
                ..Default::default()
            })?;
            let input = capture::open(&file)?;
            let mut out = output::Output::new(io::BufWriter::new(io::stdout().lock()), format);
            out.analysis_header()?;
            capture::read_records(input, |record| {
                analyzer.process(record.data, record.header, record.linktype, |event| {
                    out.analysis(&event)
                })?;
                Ok(true)
            })?;
            let incomplete = analyzer.finish(|event| out.analysis(&event))?;
            if incomplete
                + analyzer.fragments.stats.expired as usize
                + analyzer.fragments.stats.evicted as usize
                != 0
            {
                crate::report!(
                    "Oh là là! IP datagrams: {incomplete} incomplete, {} expired, {} evicted.",
                    analyzer.fragments.stats.expired,
                    analyzer.fragments.stats.evicted
                );
            }
            out.flush()
        }
        Command::Read { file, args } => {
            // Validate before opening, so malformed queries have consistent precedence.
            Filter::new(args.filter.as_deref(), args.filter_syntax)?;
            let input = capture::open(&file)?;
            packets(args, false, |emit| capture::read_records(input, emit))
        }
        Command::Flows(args) => crate::flow_command::run(args),
        #[cfg(feature = "live")]
        Command::Interfaces => live::interfaces(),
        #[cfg(feature = "live")]
        Command::Capture {
            interface,
            bpf,
            duration,
            count,
            promisc,
            args,
        } => {
            let hint =
                Filter::new(args.filter.as_deref(), args.filter_syntax)?.ethernet_prefilter();
            packets(args, true, |emit| {
                live::capture(
                    &interface,
                    (bpf.as_deref(), hint.as_deref()),
                    duration,
                    count,
                    promisc,
                    emit,
                )
            })
        }
    }
}
