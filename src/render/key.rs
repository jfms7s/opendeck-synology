//! A key's image: glyph and title on top, the value large in the middle,
//! the subject small at the bottom, on a background tinted by level.
//!
//! Text is drawn inside the image rather than sent as the native title:
//! OpenDeck paints native titles with each key's own font and size on top
//! of the image, which on a small key is hard to read.

use crate::metric::Metric;
use crate::metrics::{Level, Reading};
use crate::render::{MUTED, TEXT, accent, background, glyphs};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// Widest a text line may render, in viewBox units (of 100).
const MAX_TEXT_WIDTH: f64 = 94.0;
/// Rough average glyph advance as a fraction of font size - only used to
/// decide when a line needs squeezing, so erring wide is the safe side.
const REGULAR_CHAR_WIDTH: f64 = 0.58;
const BOLD_CHAR_WIDTH: f64 = 0.64;

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// One horizontally centred line with its baseline at `y`, squeezed with
/// `textLength` rather than clipped when it would overflow the key.
fn text_line(y: f64, size: f64, bold: bool, color: &str, content: &str) -> String {
    let char_width = if bold {
        BOLD_CHAR_WIDTH
    } else {
        REGULAR_CHAR_WIDTH
    };
    let fit = if content.chars().count() as f64 * size * char_width > MAX_TEXT_WIDTH {
        format!(r#" textLength="{MAX_TEXT_WIDTH}" lengthAdjust="spacingAndGlyphs""#)
    } else {
        String::new()
    };
    let weight = if bold { "700" } else { "500" };
    format!(
        r#"<text x="50" y="{y}" text-anchor="middle" font-family="sans-serif" font-size="{size}" font-weight="{weight}" fill="{color}"{fit}>{}</text>"#,
        escape_xml(content)
    )
}

pub fn key_svg(metric: Metric, r: &Reading) -> String {
    let bg = background(r.level);
    let glyph = glyphs::paths(metric);
    let title = format!(
        r#"<text x="30" y="21" font-family="sans-serif" font-size="14" font-weight="600" fill="{MUTED}">{}</text>"#,
        escape_xml(r.title)
    );
    let value = text_line(62.0, 28.0, true, TEXT, &r.value);
    let subject = text_line(88.0, 13.0, false, MUTED, &r.subject);
    let badge = if matches!(r.level, Level::Stale | Level::Error) {
        format!(
            r##"<circle cx="88" cy="13" r="8" fill="{}"/><text x="88" y="18" text-anchor="middle" font-family="sans-serif" font-size="13" font-weight="700" fill="#111827">!</text>"##,
            accent(r.level)
        )
    } else {
        String::new()
    };
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" fill="{bg}"/><svg x="6" y="6" width="20" height="20" viewBox="0 0 24 24"><g fill="none" stroke="{TEXT}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{glyph}</g></svg>{title}{value}{subject}{badge}</svg>"#
    )
}

/// The `image` string `setImage` expects. OpenDeck only treats it as inline
/// data when it starts with `data:`; anything else is read as a file path.
pub fn key_image(metric: Metric, r: &Reading) -> String {
    format!(
        "data:image/svg+xml;base64,{}",
        STANDARD.encode(key_svg(metric, r))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    fn reading(level: Level) -> Reading {
        Reading {
            title: "Disk",
            value: "44°C".into(),
            subject: "Drive <2> & co".into(),
            level,
            bar: Some(44.0),
            pager: None,
        }
    }

    #[test]
    fn draws_title_value_and_escaped_subject() {
        let svg = key_svg(Metric::DiskTemp, &reading(Level::Normal));
        assert!(svg.contains(">Disk</text>"), "{svg}");
        assert!(svg.contains(">44°C</text>"), "{svg}");
        assert!(svg.contains(">Drive &lt;2&gt; &amp; co</text>"), "{svg}");
    }

    #[test]
    fn background_follows_the_level_and_problems_get_a_badge() {
        let normal = key_svg(Metric::Cpu, &reading(Level::Normal));
        assert!(normal.contains(&format!(r#"fill="{}""#, background(Level::Normal))));
        assert!(!normal.contains("<circle"));
        let crit = key_svg(Metric::Cpu, &reading(Level::Crit));
        assert!(crit.contains(&format!(r#"fill="{}""#, background(Level::Crit))));
        assert!(key_svg(Metric::Cpu, &reading(Level::Stale)).contains("<circle"));
        assert!(key_svg(Metric::Cpu, &reading(Level::Error)).contains("<circle"));
    }

    #[test]
    fn long_lines_are_squeezed_to_fit() {
        let mut r = reading(Level::Normal);
        r.subject = "Hottest: M.2 Drive 1 (cache)".into();
        assert!(key_svg(Metric::DiskTemp, &r).contains(r#"textLength="94""#));
    }

    #[test]
    fn key_image_is_an_inline_svg_data_uri() {
        let uri = key_image(Metric::Cpu, &reading(Level::Normal));
        let b64 = uri.strip_prefix("data:image/svg+xml;base64,").expect(&uri);
        let svg = String::from_utf8(STANDARD.decode(b64).unwrap()).unwrap();
        assert!(svg.starts_with("<svg"));
    }
}
