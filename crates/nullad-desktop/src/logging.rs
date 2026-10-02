//! Logging setup.
//!
//! A file log is written in addition to the console, because the desktop
//! application runs from a tray with no visible console on Windows. Without a
//! file, a user reporting a problem would have nothing to attach.

use std::sync::OnceLock;

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Keeps the non-blocking writer alive for the process lifetime.
///
/// Dropping it would silently stop the file log, which is a subtle failure mode
/// worth holding a global for.
static GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();

/// Initialises tracing with console and file output.
///
/// `level` is a tracing filter directive such as `info` or `nullad_engine=debug`.
/// An invalid directive falls back to `info` rather than aborting start-up:
/// losing a log level setting must not prevent the application from running.
pub fn init(level: &str) {
    let filter = EnvFilter::try_new(level)
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let console = tracing_subscriber::fmt::layer().with_target(true);

    // A file log is best-effort: if the directory cannot be created, the
    // application still runs with console output only.
    let file_layer = match nullad_host::paths::log_dir() {
        Ok(dir) => {
            let appender = tracing_appender::rolling::daily(dir, "nullad.log");
            let (writer, guard) = tracing_appender::non_blocking(appender);
            let _ = GUARD.set(guard);
            Some(
                tracing_subscriber::fmt::layer()
                    .with_writer(writer)
                    .with_ansi(false)
                    .with_target(true),
            )
        }
        Err(_) => None,
    };

    let registry = tracing_subscriber::registry().with(filter).with(console);

    if let Some(file_layer) = file_layer {
        let _ = registry.with(file_layer).try_init();
    } else {
        let _ = registry.try_init();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_invalid_filter_directive_does_not_panic() {
        // Must not panic even though the directive is nonsense; `init` is called
        // before the UI exists, so a panic here would be an invisible crash.
        let filter = EnvFilter::try_new("not a valid directive !!!")
            .or_else(|_| EnvFilter::try_new("info"));
        assert!(filter.is_ok());
    }

    #[test]
    fn a_valid_filter_directive_is_accepted() {
        assert!(EnvFilter::try_new("info").is_ok());
        assert!(EnvFilter::try_new("nullad_engine=debug").is_ok());
    }
}
