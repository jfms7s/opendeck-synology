//! Drawing a `Reading`: `key` makes a keypad image, `dial` a touch-strip
//! payload for `assets/layouts/metric.json`. Both colour by level the same
//! way, so a key and a dial showing the same metric can never disagree.

pub mod dial;
pub mod glyphs;
pub mod key;

use crate::metrics::Level;

pub const TEXT: &str = "#f9fafb";
pub const MUTED: &str = "#d1d5db";
/// Bar colour for a healthy state-based metric (nothing to measure).
pub const NEUTRAL: &str = "#4b5563";

/// Key background: neutral, amber, red, grey.
pub fn background(level: Level) -> &'static str {
    match level {
        Level::Normal => "#111827",
        Level::Warn => "#78350f",
        Level::Crit | Level::Error => "#7f1d1d",
        Level::Stale => "#374151",
    }
}

/// Bright counterpart used for dial values, bars and the key's `!` badge.
pub fn accent(level: Level) -> &'static str {
    match level {
        Level::Normal => "#22c55e",
        Level::Warn => "#f59e0b",
        Level::Crit | Level::Error => "#ef4444",
        Level::Stale => "#9ca3af",
    }
}
