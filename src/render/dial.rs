//! A dial's touch strip (`assets/layouts/metric.json`): glyph and title,
//! the value, a bar (the measured share, or full for state metrics) and the
//! subject with a "where am I" hint when turning the dial has more views.

use crate::metric::Metric;
use crate::metrics::{Level, Reading};
use crate::render::{NEUTRAL, TEXT, accent, glyphs};
use serde_json::{Value, json};

pub fn subject_line(r: &Reading) -> String {
    match r.pager {
        Some((i, n)) if r.subject.is_empty() => format!("‹ {}/{n} ›", i + 1),
        Some((i, n)) => format!("‹ {} · {}/{n} ›", r.subject, i + 1),
        None => r.subject.clone(),
    }
}

pub fn feedback(metric: Metric, r: &Reading) -> Value {
    let value_color = if r.level == Level::Normal {
        TEXT
    } else {
        accent(r.level)
    };
    let bar_color = if r.bar.is_none() && r.level == Level::Normal {
        NEUTRAL
    } else {
        accent(r.level)
    };
    json!({
        "icon": glyphs::svg(metric),
        "title": r.title,
        "value": { "value": r.value, "color": value_color },
        "bar": { "value": r.bar.unwrap_or(100.0), "bar_fill_c": bar_color },
        "subject": subject_line(r),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading() -> Reading {
        Reading {
            title: "Pool",
            value: "Rebuild 43%".into(),
            subject: "Pool 2".into(),
            level: Level::Warn,
            bar: Some(43.0),
            pager: Some((1, 2)),
        }
    }

    #[test]
    fn feedback_keys_match_the_shipped_layout() {
        let layout: Value =
            serde_json::from_str(include_str!("../../assets/layouts/metric.json")).unwrap();
        let keys: Vec<&str> = layout["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["key"].as_str().unwrap())
            .collect();
        let fb = feedback(Metric::Pool, &reading());
        for k in fb.as_object().unwrap().keys() {
            assert!(keys.contains(&k.as_str()), "layout has no item keyed {k}");
        }
    }

    #[test]
    fn feedback_colours_value_and_bar_by_level() {
        let fb = feedback(Metric::Pool, &reading());
        assert_eq!(fb["value"]["value"], "Rebuild 43%");
        assert_eq!(fb["value"]["color"], accent(Level::Warn));
        assert_eq!(fb["bar"]["value"], 43.0);
        assert_eq!(fb["bar"]["bar_fill_c"], accent(Level::Warn));
        assert_eq!(fb["title"], "Pool");
        assert!(fb["icon"].as_str().unwrap().starts_with("<svg"));
    }

    #[test]
    fn state_readings_fill_the_bar() {
        let mut r = reading();
        r.bar = None;
        r.level = Level::Normal;
        let fb = feedback(Metric::Pool, &r);
        assert_eq!(fb["bar"]["value"], 100.0);
        assert_eq!(fb["value"]["color"], TEXT);
        assert_eq!(fb["bar"]["bar_fill_c"], NEUTRAL);
    }

    #[test]
    fn subject_shows_where_rotation_is() {
        assert_eq!(subject_line(&reading()), "‹ Pool 2 · 2/2 ›");
        let mut r = reading();
        r.subject.clear();
        assert_eq!(subject_line(&r), "‹ 2/2 ›");
        r.pager = None;
        r.subject = "Usage".into();
        assert_eq!(subject_line(&r), "Usage");
    }
}
