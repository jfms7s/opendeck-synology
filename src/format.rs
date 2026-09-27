//! How numbers look on a key. Sizes use binary multiples but DSM's labels
//! (a GiB shows as "GB"), so the plugin agrees with DSM's own UI.

use crate::settings::TempUnit;

const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];

pub fn percent(v: f64) -> String {
    format!("{v:.0}%")
}

pub fn temperature(celsius: f64, unit: TempUnit) -> String {
    match unit {
        TempUnit::Celsius => format!("{celsius:.0}°C"),
        TempUnit::Fahrenheit => format!("{:.0}°F", celsius * 9.0 / 5.0 + 32.0),
    }
}

/// (value scaled into the largest unit where it is >= 1, that unit's index)
/// A value that rounds to 1024 in its current unit moves to the next unit.
fn scale(n: u64) -> (f64, usize) {
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1023.5 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    (v, i)
}

/// One decimal below 10 ("6.0"), none above ("16"); bytes never get decimals.
fn number(v: f64, unit: usize) -> String {
    if unit == 0 || v >= 9.95 {
        format!("{v:.0}")
    } else {
        format!("{v:.1}")
    }
}

pub fn bytes(n: u64) -> String {
    let (v, i) = scale(n);
    format!("{} {}", number(v, i), UNITS[i])
}

/// "5.0/7.0 TB": both numbers in the unit of the total.
pub fn used_of_total(used: u64, total: u64) -> String {
    let (t, i) = scale(total);
    let u = used as f64 / 1024f64.powi(i as i32);
    format!("{}/{} {}", number(u, i), number(t, i), UNITS[i])
}

pub fn rate(bytes_per_sec: u64) -> String {
    let (v, i) = scale(bytes_per_sec);
    let n = if i == 0 || v >= 99.95 {
        format!("{v:.0}")
    } else {
        format!("{v:.1}")
    };
    format!("{n} {}/s", UNITS[i])
}

pub fn uptime(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, secs % 86_400 / 3600, secs % 3600 / 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}

pub fn load(v: f64) -> String {
    format!("{v:.2}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;
    const TIB: u64 = 1024 * GIB;

    #[test]
    fn percentages_round_to_whole_numbers() {
        assert_eq!(percent(37.4), "37%");
        assert_eq!(percent(99.6), "100%");
    }

    #[test]
    fn temperatures_follow_the_unit() {
        assert_eq!(temperature(48.0, TempUnit::Celsius), "48°C");
        assert_eq!(temperature(48.0, TempUnit::Fahrenheit), "118°F");
    }

    #[test]
    fn bytes_use_binary_multiples_with_dsm_labels() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(6 * GIB), "6.0 GB");
        assert_eq!(bytes(16 * GIB), "16 GB");
        assert_eq!(bytes(7 * TIB + TIB / 2), "7.5 TB");
    }

    #[test]
    fn used_of_total_shares_the_totals_unit() {
        assert_eq!(used_of_total(6 * GIB, 16 * GIB), "6.0/16 GB");
        assert_eq!(
            used_of_total(5_452_800_000_000, 7_680_000_000_000),
            "5.0/7.0 TB"
        );
        assert_eq!(used_of_total(512 * 1024 * 1024, 2 * TIB), "0.0/2.0 TB");
    }

    #[test]
    fn rates_scale_per_second() {
        assert_eq!(rate(900), "900 B/s");
        assert_eq!(rate(524_288), "512 KB/s");
        assert_eq!(rate(13_002_342), "12.4 MB/s");
        assert_eq!(rate(150 * 1024 * 1024), "150 MB/s");
    }

    #[test]
    fn uptime_shows_the_two_largest_units() {
        assert_eq!(uptime(1_055_111), "12d 5h");
        assert_eq!(uptime(4 * 3600 + 12 * 60), "4h 12m");
        assert_eq!(uptime(59), "0m");
    }

    #[test]
    fn load_averages_have_two_decimals() {
        assert_eq!(load(0.42), "0.42");
        assert_eq!(load(3.0), "3.00");
    }

    #[test]
    fn values_that_round_up_to_a_threshold_take_the_next_format() {
        assert_eq!(bytes(1_048_064), "1.0 MB");
        assert_eq!(bytes(10_199), "10 KB");
        assert_eq!(rate(102_349), "100 KB/s");
    }
}
