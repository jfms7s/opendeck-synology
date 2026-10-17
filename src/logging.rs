//! The plugin's logger: `simplelog` behind a filter that keeps secrets
//! carried by OpenDeck messages out of the log.
//!
//! openaction logs the whole text of any inbound frame it cannot parse
//! (`Unknown event received: {frame}`, target `openaction::inbound`). Two
//! frames carry secrets (the panel's `saveConnection` with the typed password,
//! and `didReceiveGlobalSettings` holding the settings-file password), so such
//! a frame must never reach the log as written.

use log::{LevelFilter, Log, Metadata, Record};

/// The line logged in place of an unparsed OpenDeck message.
pub const UNRECOGNISED: &str = "unrecognised OpenDeck message (not logged: it may hold secrets)";

/// The replacement text for a record that may hold an OpenDeck message, or
/// `None` to log it as written.
pub fn redact(target: &str, message: &str) -> Option<&'static str> {
    (target.starts_with("openaction") && message.starts_with("Unknown event received"))
        .then_some(UNRECOGNISED)
}

/// Forwards every record to the inner logger, except that a record [`redact`]
/// picks goes out with the fixed text instead (same level and target).
pub struct Redacting<L>(pub L);

impl<L: Log> Log for Redacting<L> {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.0.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        // Only openaction's records need formatting to be checked.
        if record.target().starts_with("openaction")
            && let Some(text) = redact(record.target(), &record.args().to_string())
        {
            self.0.log(
                &Record::builder()
                    .args(format_args!("{text}"))
                    .level(record.level())
                    .target(record.target())
                    .module_path(record.module_path())
                    .file(record.file())
                    .line(record.line())
                    .build(),
            );
            return;
        }
        self.0.log(record);
    }

    fn flush(&self) {
        self.0.flush();
    }
}

/// The logger `main` installs: `SimpleLogger` at `Info`, wrapped.
pub fn logger() -> Redacting<Box<simplelog::SimpleLogger>> {
    Redacting(simplelog::SimpleLogger::new(
        LevelFilter::Info,
        simplelog::Config::default(),
    ))
}

/// Installs [`logger`] as the process logger.
pub fn init() {
    log::set_boxed_logger(Box::new(logger())).expect("logger init");
    log::set_max_level(LevelFilter::Info);
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::Level;
    use std::sync::Mutex;

    /// Keeps every record it gets as `(level, target, text)`.
    #[derive(Default)]
    struct Capture(Mutex<Vec<(Level, String, String)>>);

    impl Log for Capture {
        fn enabled(&self, _: &Metadata) -> bool {
            true
        }
        fn log(&self, record: &Record) {
            self.0.lock().unwrap().push((
                record.level(),
                record.target().to_owned(),
                record.args().to_string(),
            ));
        }
        fn flush(&self) {}
    }

    fn send(logger: &impl Log, level: Level, target: &str, text: &str) {
        logger.log(
            &Record::builder()
                .args(format_args!("{text}"))
                .level(level)
                .target(target)
                .build(),
        );
    }

    fn captured(logger: Redacting<Capture>) -> Vec<(Level, String, String)> {
        logger.0.0.into_inner().unwrap()
    }

    #[test]
    fn an_unparsed_message_holding_a_password_is_never_logged() {
        let logger = Redacting(Capture::default());
        send(
            &logger,
            Level::Warn,
            "openaction::inbound",
            r#"Unknown event received: {"event":"sendToPlugin","payload":{"event":"saveConnection","password":"hunter2"}}"#,
        );
        let lines = captured(logger);
        assert!(
            lines.iter().all(|(_, _, text)| !text.contains("hunter2")),
            "password logged: {lines:?}"
        );
        assert_eq!(
            lines,
            [(
                Level::Warn,
                "openaction::inbound".to_owned(),
                UNRECOGNISED.to_owned()
            )]
        );
    }

    #[test]
    fn other_records_pass_through_unchanged() {
        let logger = Redacting(Capture::default());
        let records = [
            (
                Level::Error,
                "openaction::inbound",
                "Failed to process inbound event: x",
            ),
            (
                Level::Error,
                "openaction::inbound",
                "Failed to run plugin ready handler: y",
            ),
            (
                Level::Warn,
                "opendeck_synology::services",
                "Unknown event received: the plugin's own words",
            ),
            (Level::Info, "opendeck_synology", "connected"),
        ];
        for (level, target, text) in records {
            send(&logger, level, target, text);
        }
        let expected: Vec<_> = records
            .iter()
            .map(|&(l, t, x)| (l, t.to_owned(), x.to_owned()))
            .collect();
        assert_eq!(captured(logger), expected);
    }

    #[test]
    fn redact_picks_only_openactions_unknown_event_line() {
        assert_eq!(
            redact("openaction::inbound", "Unknown event received: {}"),
            Some(UNRECOGNISED)
        );
        assert_eq!(
            redact("openaction::inbound", "Failed to process inbound event: x"),
            None
        );
        assert_eq!(
            redact("opendeck_synology", "Unknown event received: {}"),
            None
        );
    }

    #[test]
    fn the_installed_logger_is_simplelog_at_info() {
        let logger = logger();
        let meta = |level| Metadata::builder().level(level).target("t").build();
        assert!(logger.enabled(&meta(Level::Info)));
        assert!(!logger.enabled(&meta(Level::Debug)));
    }
}
