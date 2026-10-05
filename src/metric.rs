//! The catalogue: which metrics exist, which DSM endpoint feeds each, and
//! their defaults.

pub use crate::dsm::endpoint::Endpoint;
use serde::Serialize;

/// Which per-key settings a metric has, for the settings panel - so the
/// panel's controls come from the same catalogue as everything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Fields {
    /// Label of the "which one" dropdown (disk, volume, interface...).
    pub target: Option<&'static str>,
    pub cpu_view: bool,
    pub direction: bool,
    pub amount: bool,
    /// Unit of the warn/critical thresholds, if the metric has them.
    pub threshold_unit: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Metric {
    Cpu,
    Ram,
    Network,
    SysTemp,
    Uptime,
    DiskTemp,
    DiskHealth,
    Volume,
    Pool,
    Update,
}

impl Metric {
    #[cfg(test)]
    pub const ALL: [Metric; 10] = [
        Self::Cpu,
        Self::Ram,
        Self::Network,
        Self::SysTemp,
        Self::Uptime,
        Self::DiskTemp,
        Self::DiskHealth,
        Self::Volume,
        Self::Pool,
        Self::Update,
    ];

    pub fn endpoint(self) -> Endpoint {
        match self {
            Self::Cpu | Self::Ram | Self::Network => Endpoint::Utilization,
            Self::SysTemp | Self::Uptime => Endpoint::SystemInfo,
            Self::DiskTemp | Self::DiskHealth | Self::Volume | Self::Pool => Endpoint::Storage,
            Self::Update => Endpoint::Update,
        }
    }

    /// `const` so each action type can use it as its `Action::UUID`.
    pub const fn uuid(self) -> &'static str {
        match self {
            Self::Cpu => "com.jfms7s.synology.cpu",
            Self::Ram => "com.jfms7s.synology.ram",
            Self::Network => "com.jfms7s.synology.network",
            Self::SysTemp => "com.jfms7s.synology.systemp",
            Self::Uptime => "com.jfms7s.synology.uptime",
            Self::DiskTemp => "com.jfms7s.synology.disktemp",
            Self::DiskHealth => "com.jfms7s.synology.diskhealth",
            Self::Volume => "com.jfms7s.synology.volume",
            Self::Pool => "com.jfms7s.synology.pool",
            Self::Update => "com.jfms7s.synology.update",
        }
    }

    /// Short heading drawn on keys and dials.
    pub fn title(self) -> &'static str {
        match self {
            Self::Cpu => "CPU",
            Self::Ram => "RAM",
            Self::Network => "Network",
            Self::SysTemp => "System",
            Self::Uptime => "Uptime",
            Self::DiskTemp => "Disk",
            Self::DiskHealth => "Health",
            Self::Volume => "Volume",
            Self::Pool => "Pool",
            Self::Update => "DSM",
        }
    }

    pub fn fields(self) -> Fields {
        let none = Fields::default();
        match self {
            Self::Cpu => Fields {
                cpu_view: true,
                threshold_unit: Some("%"),
                ..none
            },
            Self::Ram => Fields {
                amount: true,
                threshold_unit: Some("%"),
                ..none
            },
            Self::Network => Fields {
                target: Some("Interface"),
                direction: true,
                threshold_unit: Some("MB/s"),
                ..none
            },
            Self::SysTemp => Fields {
                threshold_unit: Some("°C"),
                ..none
            },
            Self::DiskTemp => Fields {
                target: Some("Disk"),
                threshold_unit: Some("°C"),
                ..none
            },
            Self::DiskHealth => Fields {
                target: Some("Disk"),
                ..none
            },
            Self::Volume => Fields {
                target: Some("Volume"),
                amount: true,
                threshold_unit: Some("%"),
                ..none
            },
            Self::Pool => Fields {
                target: Some("Pool"),
                ..none
            },
            Self::Uptime | Self::Update => none,
        }
    }

    /// (warn, crit) for numeric metrics. Temperatures are in °C. `None` =
    /// state-based, or no thresholds unless the user sets some (network).
    pub fn default_thresholds(self) -> Option<(f64, f64)> {
        match self {
            Self::Cpu => Some((70.0, 90.0)),
            Self::Ram => Some((80.0, 95.0)),
            Self::SysTemp => Some((60.0, 70.0)),
            Self::DiskTemp => Some((50.0, 60.0)),
            Self::Volume => Some((80.0, 90.0)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn uuids_are_unique_and_namespaced() {
        let uuids: HashSet<_> = Metric::ALL.iter().map(|m| m.uuid()).collect();
        assert_eq!(uuids.len(), 10);
        assert!(uuids.iter().all(|u| u.starts_with("com.jfms7s.synology.")));
    }

    #[test]
    fn storage_metrics_share_one_endpoint() {
        for m in [
            Metric::DiskTemp,
            Metric::DiskHealth,
            Metric::Volume,
            Metric::Pool,
        ] {
            assert_eq!(m.endpoint(), Endpoint::Storage);
        }
        assert_eq!(Metric::Cpu.endpoint(), Endpoint::Utilization);
        assert_eq!(Metric::Uptime.endpoint(), Endpoint::SystemInfo);
        assert_eq!(Metric::Update.endpoint(), Endpoint::Update);
    }

    #[test]
    fn metrics_with_thresholds_say_in_which_unit() {
        for m in Metric::ALL {
            if m.default_thresholds().is_some() {
                assert!(m.fields().threshold_unit.is_some(), "{m:?}");
            }
        }
        assert_eq!(Metric::Network.fields().threshold_unit, Some("MB/s"));
        assert_eq!(Metric::Pool.fields().target, Some("Pool"));
        assert_eq!(Metric::Update.fields(), Fields::default());
    }

    #[test]
    fn only_numeric_metrics_have_default_thresholds() {
        assert_eq!(Metric::Cpu.default_thresholds(), Some((70.0, 90.0)));
        assert_eq!(Metric::DiskTemp.default_thresholds(), Some((50.0, 60.0)));
        assert_eq!(Metric::Network.default_thresholds(), None);
        assert_eq!(Metric::Pool.default_thresholds(), None);
    }
}
