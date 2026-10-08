use clap::Command;
use std::fmt::Write;
/// Derive the alias table from Clap so help and executable command names agree.
pub fn root(command: &Command) -> String {
    let mut table = String::from("Commands:\n  COMMAND      ALIAS                 PURPOSE\n");
    for sub in command.get_subcommands().filter(|c| !c.is_hide_set()) {
        let aliases = sub
            .get_all_aliases()
            .filter(|name| *name != "choclate")
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            table,
            "  {:12} {:21} {}",
            sub.get_name(),
            if aliases.is_empty() { "-" } else { &aliases },
            sub.get_about().map(ToString::to_string).unwrap_or_default()
        );
    }
    format!("{{about-with-newline}}\n{{usage-heading}} {{usage}}\n\n{table}\nOptions:\n{{options}}\nExamples:\n  crepe read traffic.pcap 'ip.src == 192.0.2.10' -vvX\n  crepe flows traffic.pcap --store ./flows\n  crepe flows ./flows '* | sort bytes desc | limit 10'\n  crepe forensics incident.pcap\n\nUse crepe COMMAND --help for filters, queries and examples.\nAliases select the same workflow; --serious changes diagnostics only.\n")
}
