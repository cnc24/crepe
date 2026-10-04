//! Human flair is presentation only; structured logs retain stable codes.
use std::sync::atomic::{AtomicBool, Ordering};
static SERIOUS: AtomicBool = AtomicBool::new(false);
static JSON: AtomicBool = AtomicBool::new(false);

pub(crate) fn configure(serious: bool, json: bool) {
    SERIOUS.store(serious, Ordering::Relaxed);
    JSON.store(json, Ordering::Relaxed);
}
pub(crate) fn apply_flair(flair: bool) {
    if !flair {
        SERIOUS.store(true, Ordering::Relaxed);
    }
}
pub(crate) fn flair_enabled() -> bool {
    !SERIOUS.load(Ordering::Relaxed) && !JSON.load(Ordering::Relaxed)
}
pub(crate) fn emit(args: std::fmt::Arguments<'_>) {
    let original = args.to_string();
    let mut message = original.as_str();
    let mut severity = "info";
    for (prefix, level) in [
        ("Sacré bleu! ", "error"),
        ("Zut alors! ", "warning"),
        ("Oh là là! ", "warning"),
        ("Mon dieu! ", "error"),
        ("Quelle catastrophe! ", "error"),
        ("Voilà! ", "info"),
        ("Magnifique! ", "info"),
        ("Bon appétit! ", "info"),
    ] {
        if let Some(rest) = message.strip_prefix(prefix) {
            message = rest;
            severity = level;
            break;
        }
    }
    if JSON.load(Ordering::Relaxed) {
        let code = message
            .strip_prefix('[')
            .and_then(|s| s.split_once(']'))
            .filter(|(code, _)| code.starts_with("CREPE-"));
        let (code, detail) = match code {
            Some((code, detail)) => (Some(code), detail.trim_start()),
            None => (None, message),
        };
        eprintln!(
            "{}",
            serde_json::json!({"severity":severity,"code":code,"message":detail})
        );
    } else if SERIOUS.load(Ordering::Relaxed) {
        eprintln!("{message}");
    } else {
        eprintln!("{original}");
    }
}
#[macro_export]
macro_rules! report {
    ($($arg:tt)*) => { $crate::reporting::emit(format_args!($($arg)*)) };
}
