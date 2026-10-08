mod application;
mod args;
mod commands;
mod flow_command;
mod flow_display;
mod help;
mod history;
mod link_display;
#[cfg(feature = "live")]
mod live;
mod metrics;
mod output;
mod packet_display;
mod packet_filter;
mod recipes;
mod reporting;
mod update;
#[cfg(feature = "live")]
mod windows;
use args::{Cli, Format};
use clap::{CommandFactory, FromArgMatches};
use crepe_core::Error;
use std::{
    io::{self, IsTerminal},
    process::ExitCode,
};

fn output_error(e: io::Error) -> Error {
    Error::new(
        if e.kind() == io::ErrorKind::BrokenPipe {
            "CREPE-IO-PIPE"
        } else {
            "CREPE-IO-002"
        },
        e,
    )
}

fn main() -> ExitCode {
    // Configure parse-error reporting as well; stop at the option terminator.
    let early: Vec<_> = std::env::args().skip(1).take_while(|a| a != "--").collect();
    reporting::configure(
        early.iter().any(|a| a == "--serious"),
        early.iter().any(|a| a == "--log-format=json")
            || early.windows(2).any(|w| w == ["--log-format", "json"]),
    );
    let command = help::configure(Cli::command());
    let template = help::root(&command);
    let template = if io::stdout().is_terminal() && reporting::flair_enabled() {
        format!("{}\n{template}", help::LOGO)
    } else {
        template
    };
    let cli = match command
        .help_template(template)
        .try_get_matches()
        .and_then(|matches| Cli::from_arg_matches(&matches))
    {
        Ok(cli) => cli,
        Err(e) => {
            if matches!(
                e.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                let _ = e.print();
                return ExitCode::SUCCESS;
            }
            crate::report!("Zut alors! [CREPE-CLI-001] {e}");
            return ExitCode::from(2);
        }
    };
    reporting::configure(cli.serious, matches!(cli.log_format, args::LogFormat::Json));
    let _metrics = match cli.metrics.map(metrics::Server::start).transpose() {
        Ok(server) => server,
        Err(error) => {
            crate::report!("Sacré bleu! {error}");
            return ExitCode::from(1);
        }
    };
    match commands::run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if e.code == "CREPE-IO-PIPE" => ExitCode::SUCCESS,
        Err(e) => {
            crate::report!("Sacré bleu! {e}");
            ExitCode::from(if matches!(e.code, "CREPE-CQL-001" | "CREPE-CLI-001") {
                2
            } else {
                1
            })
        }
    }
}
