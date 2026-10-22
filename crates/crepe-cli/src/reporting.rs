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
pub(crate) fn emit(level: &str, neutral: bool, args: std::fmt::Arguments<'_>) {
    let original = args.to_string();
    let mut message = original.as_str();
    for prefix in [
        "Sacré bleu! ",
        "Zut alors! ",
        "Oh là là! ",
        "Mon dieu! ",
        "Quelle catastrophe! ",
        "Voilà! ",
        "Magnifique! ",
        "Bon appétit! ",
    ] {
        if let Some(rest) = message.strip_prefix(prefix) {
            message = rest;
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
            serde_json::json!({"severity":level,"code":code,"message":detail})
        );
    } else if neutral || SERIOUS.load(Ordering::Relaxed) {
        eprintln!("{message}");
    } else {
        eprintln!("{original}");
    }
}
#[macro_export]
macro_rules! report {
    (error, $($arg:tt)*) => { $crate::reporting::emit("error", true, format_args!($($arg)*)) };
    (usage, $($arg:tt)*) => { $crate::reporting::emit("error", false, format_args!($($arg)*)) };
    (warning, $($arg:tt)*) => { $crate::reporting::emit("warning", true, format_args!($($arg)*)) };
    ($($arg:tt)*) => { $crate::reporting::emit("info", false, format_args!($($arg)*)) };
}
