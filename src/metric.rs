//! The catalogue: which metrics exist, which DSM endpoint feeds each, and
//! their defaults.

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endpoint {
    Utilization,
    SystemInfo,
    Storage,
    Update,
}

impl Endpoint {
    pub const ALL: [Endpoint; 4] = [
        Self::Utilization,
        Self::SystemInfo,
        Self::Storage,
        Self::Update,
    ];

    pub fn default_interval(self) -> Duration {
        Duration::from_secs(match self {
            Self::Utilization => 5,
            Self::SystemInfo => 30,
            Self::Storage => 60,
            Self::Update => 6 * 3600,
        })
    }
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
    fn default_intervals_match_the_spec() {
        assert_eq!(Endpoint::Utilization.default_interval().as_secs(), 5);
        assert_eq!(Endpoint::SystemInfo.default_interval().as_secs(), 30);
        assert_eq!(Endpoint::Storage.default_interval().as_secs(), 60);
        assert_eq!(Endpoint::Update.default_interval().as_secs(), 6 * 3600);
    }

    #[test]
    fn only_numeric_metrics_have_default_thresholds() {
        assert_eq!(Metric::Cpu.default_thresholds(), Some((70.0, 90.0)));
        assert_eq!(Metric::DiskTemp.default_thresholds(), Some((50.0, 60.0)));
        assert_eq!(Metric::Network.default_thresholds(), None);
        assert_eq!(Metric::Pool.default_thresholds(), None);
    }
}
