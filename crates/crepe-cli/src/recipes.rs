//! Friendly recipe commands share the historical ingestion engine.
use crate::args::RecipeArgs;
use crepe_core::{Error, Result};
use crepe_engine::Profile;
use std::io::{self, IsTerminal, Write};

fn input(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    io::stderr().flush().map_err(crate::output_error)?;
    let mut value = String::new();
    io::stdin()
        .read_line(&mut value)
        .map_err(|e| Error::new("CREPE-CLI-001", e))?;
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::new("CREPE-CLI-001", "No source selected."));
    }
    Ok(value.into())
}

fn select_source(profile: Profile, args: &mut RecipeArgs) -> Result<()> {
    if !io::stdin().is_terminal() {
        return Err(Error::new(
            "CREPE-CLI-001",
            "Choose a capture file or --interface NAME; run this recipe in a terminal for the source menu.",
        ));
    }
    let (description, aside) = match profile {
        Profile::Chocolate => (
            "Chocolate: deep network analysis of packets, flows and DNS/TLS/HTTP/SSH metadata.",
            "Layers of insight, served without decrypting your TLS.",
        ),
        Profile::Suzette => (
            "Suzette: investigate traffic and optionally save observations with --store for later queries.",
            "Follow the evidence; leave the flambé to the kitchen.",
        ),
        Profile::Maison => (
            "Maison: analyze traffic using the profile and settings from your configuration.",
            "Your recipe, our kitchen.",
        ),
        Profile::Complete => (
            "Complete: run all available packet-analysis engines; add --listen for NetFlow/IPFIX collection.",
            "The full menu, with resource limits included.",
        ),
        Profile::Sucre => ("Sucre: inspect captured packets.", "The simple recipe."),
        Profile::Banane => ("Banane: receive NetFlow/IPFIX records.", "Let the flows come to you."),
    };
    crate::report!("{description}");
    let prompt = if crate::reporting::flair_enabled() {
        crate::report!("Bon appétit! {aside}");
        "Choose your ingredients:"
    } else {
        "Choose a source:"
    };
    crate::report!("{prompt}\n  1  Capture file\n  2  Live network interface");
    match input("Source [1/2]: ")?.as_str() {
        "1" => args.file = Some(input("Capture file path: ")?.into()),
        "2" => {
            #[cfg(feature = "live")]
            {
                let interfaces = crepe_capture::live::interfaces()?;
                for (index, interface) in interfaces.iter().enumerate() {
                    crate::report!("  {}  {}", index + 1, interface.name);
                }
                let choice = input("Interface number: ")?;
                let interface = choice
                    .parse::<usize>()
                    .ok()
                    .and_then(|n| n.checked_sub(1))
                    .and_then(|n| interfaces.get(n))
                    .ok_or_else(|| Error::new("CREPE-CLI-001", "Invalid interface selection."))?;
                args.interface = Some(interface.name.clone());
            }
            #[cfg(not(feature = "live"))]
            return Err(Error::new(
                "CREPE-CAP-001",
                "This build has no live capture support.",
            ));
        }
        _ => {
            return Err(Error::new(
                "CREPE-CLI-001",
                "Choose 1 for a file or 2 for live capture.",
            ))
        }
    }
    Ok(())
}

pub(crate) fn run(profile: Profile, mut args: RecipeArgs) -> Result<()> {
    let mut config = crate::history::config(args.config.as_deref())?;
    if args.file.is_none() && args.interface.is_none() {
        args.interface = config.interface.clone();
    }
    if args.store.is_none() {
        args.store = config.store.clone();
    }
    args.listen = args.listen.or(config.collector_listen);
    if let Some(workers) = args.workers {
        config.workers = workers as usize;
    }
    config.tolerant_decode |= args.tolerant;
    if args.enable.iter().any(|module| module == "notices") {
        config.notices = true;
    }
    config.disabled_modules.retain(|m| !args.enable.contains(m));
    config.disabled_modules.extend(args.disable.iter().cloned());
    if config.disabled_modules.iter().any(|m| m == "notices") {
        config.notices = false;
    }
    config.validate()?;
    if !matches!(profile, Profile::Maison) {
        config.profile = profile;
    }
    if matches!(config.profile, Profile::Banane) {
        return Err(Error::new(
            "CREPE-CONFIG-001",
            "Use crepe banane to run the UDP collector.",
        ));
    }
    if args.file.is_none() && args.interface.is_none() {
        select_source(profile, &mut args)?;
    }
    if (args.listen.is_some() || args.query.is_some()) && args.interface.is_none() {
        return Err(Error::new(
            "CREPE-CONFIG-001",
            "live collection/query requires a network interface, not a capture file",
        ));
    }
    if let Some(interface) = &args.interface {
        #[cfg(feature = "live")]
        {
            let source = crepe_storage::identity(&[
                &config.sensor,
                interface,
                &std::process::id().to_string(),
                &std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| Error::new("CREPE-CAP-001", e))?
                    .as_nanos()
                    .to_string(),
            ]);
            let window = args
                .query
                .as_deref()
                .map(|query| crate::windows::Window::new(query, args.query_interval))
                .transpose()?
                .map(std::cell::RefCell::new);
            let mut exporter = args
                .listen
                .map(crate::history::ExportSource::bind)
                .transpose()?;
            let summary = crepe_engine::stream_inputs(
                &source,
                args.store.as_deref(),
                &config,
                |emit| {
                    crate::live::capture_events(
                        interface,
                        (None, None),
                        args.duration,
                        None,
                        false,
                        |record, now| {
                            if let Some(exporter) = &mut exporter {
                                exporter.poll(&config.sensor, &source, &mut |row| {
                                    emit(crepe_engine::Input::Observation(Box::new(row)))
                                })?;
                            }
                            let more = emit(match record {
                                Some(record) => crepe_engine::Input::Packet(record),
                                None => crepe_engine::Input::Tick(now),
                            })?;
                            if let Some(window) = &window {
                                window.borrow_mut().flush(false)?;
                            }
                            Ok(more)
                        },
                    )
                },
                &mut |row| {
                    crate::metrics::EVENTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    match &window {
                        Some(window) => window.borrow_mut().push(row),
                        None => crate::history::print_json(row),
                    }
                },
            )?;
            if let Some(window) = &window {
                window.borrow_mut().flush(true)?;
            }
            crate::report!(
                "Magnifique! {} packets, {} observations.",
                summary.packets,
                summary.observations
            );
            return Ok(());
        }
        #[cfg(not(feature = "live"))]
        {
            let _ = interface;
            return Err(Error::new(
                "CREPE-CAP-001",
                "This build has no live capture support.",
            ));
        }
    }
    let temp = tempfile::Builder::new()
        .prefix("crepe-recipe-")
        .tempdir()
        .map_err(|e| Error::new("CREPE-IO-002", e))?;
    let file = args
        .file
        .as_deref()
        .ok_or_else(|| Error::new("CREPE-CLI-001", "No source selected."))?;
    let store = args
        .store
        .clone()
        .unwrap_or_else(|| temp.path().join("history"));
    let summary = crepe_engine::ingest(file, &store, &config)?;
    crate::report!("Magnifique! {} packets, {} observations. Showing at most 10,000 observations as JSON Lines.", summary.packets, summary.observations);
    if args.store.is_some() {
        crate::report!("History saved to {}", store.display());
    } else if summary.observations > 10_000 {
        crate::report!("Oh là là! Use --store PATH to retain and query all observations.");
    }
    crate::history::query(&store, "* | sort timestamp | limit 10000")
}
