//! One line-art glyph per metric, drawn on a 24×24 grid with round strokes.

use crate::metric::Metric;
use crate::render::TEXT;

pub fn paths(metric: Metric) -> &'static str {
    match metric {
        Metric::Cpu => {
            r#"<rect x="6" y="6" width="12" height="12" rx="1"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>"#
        }
        Metric::Ram => {
            r#"<rect x="2" y="7" width="20" height="10" rx="1"/><path d="M6 11v2M10 11v2M14 11v2M18 11v2M5 17v3M19 17v3"/>"#
        }
        Metric::Network => r#"<path d="M7 4v14M3 14l4 4 4-4M17 20V6M13 10l4-4 4 4"/>"#,
        Metric::SysTemp | Metric::DiskTemp => {
            r#"<path d="M14 14.8V4a2 2 0 0 0-4 0v10.8a4 4 0 1 0 4 0z"/><path d="M12 18v-6"/>"#
        }
        Metric::Uptime => r#"<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>"#,
        Metric::DiskHealth => r#"<path d="M3 12h4l2-5 4 10 2-5h6"/>"#,
        Metric::Volume => {
            r#"<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>"#
        }
        Metric::Pool => r#"<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/>"#,
        Metric::Update => r#"<path d="M12 3v12M7 10l5 5 5-5M4 20h16"/>"#,
    }
}

/// A standalone SVG of the glyph, as a dial `pixmap` item accepts it.
pub fn svg(metric: Metric) -> String {
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><g fill="none" stroke="{TEXT}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{}</g></svg>"#,
        paths(metric)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_metric_has_a_glyph() {
        for m in Metric::ALL {
            let svg = svg(m);
            assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
            assert!(!paths(m).is_empty(), "{m:?}");
        }
    }

    /// A 144×144 action icon: the glyph, white on the plugin's dark tile.
    fn icon_svg(metric: Metric) -> String {
        format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 144 144"><rect width="144" height="144" rx="24" fill="#111827"/><svg x="30" y="30" width="84" height="84" viewBox="0 0 24 24"><g fill="none" stroke="{TEXT}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{}</g></svg></svg>"##,
            paths(metric)
        )
    }

    /// Writes the SVG sources of the PNG icons. Use `scripts/render-icons.sh`,
    /// which runs this and converts the result.
    #[test]
    #[ignore]
    fn write_icon_sources() {
        let dir = format!("{}/assets/icon-src", env!("CARGO_MANIFEST_DIR"));
        std::fs::create_dir_all(&dir).unwrap();
        for m in Metric::ALL {
            let name = m.uuid().rsplit('.').next().unwrap();
            std::fs::write(format!("{dir}/{name}.svg"), icon_svg(m)).unwrap();
        }
        // The plugin's own icon: a NAS is, above all, its storage pool.
        std::fs::write(format!("{dir}/icon.svg"), icon_svg(Metric::Pool)).unwrap();
    }
}
