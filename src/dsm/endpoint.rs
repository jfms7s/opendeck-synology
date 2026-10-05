//! The four DSM endpoints the plugin polls: which API and method each one
//! calls, how often by default, and how its answer is parsed.

use crate::dsm::api::{STORAGE, SYSTEM, UPGRADE, UTILIZATION};
use crate::dsm::error::DsmError;
use crate::dsm::model::{self, Payload};
use crate::dsm::session::Session;
use serde_json::Value;
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

    /// Position in `ALL`, for per-endpoint arrays.
    pub fn index(self) -> usize {
        self as usize
    }

    pub fn api(self) -> &'static str {
        match self {
            Self::Utilization => UTILIZATION,
            Self::SystemInfo => SYSTEM,
            Self::Storage => STORAGE,
            Self::Update => UPGRADE,
        }
    }

    pub fn method(self) -> &'static str {
        match self {
            Self::Utilization => "get",
            Self::SystemInfo => "info",
            Self::Storage => "load_info",
            Self::Update => "check",
        }
    }

    /// The API version this plugin is written against (see `api::wanted`).
    pub fn version(self) -> u64 {
        1
    }

    pub fn default_interval(self) -> Duration {
        Duration::from_secs(match self {
            Self::Utilization => 5,
            Self::SystemInfo => 30,
            Self::Storage => 60,
            Self::Update => 6 * 3600,
        })
    }

    pub fn parse(self, data: &Value) -> Result<Payload, String> {
        match self {
            Self::Utilization => model::parse_utilization(data).map(Payload::Utilization),
            Self::SystemInfo => model::parse_system_info(data).map(Payload::SystemInfo),
            Self::Storage => model::parse_storage(data).map(Payload::Storage),
            Self::Update => model::parse_update(data).map(Payload::Update),
        }
    }

    /// Calls this endpoint on `session` and parses the answer.
    pub async fn fetch(self, session: &Session) -> Result<Payload, DsmError> {
        let data = session.call(self.api(), self.method(), &[]).await?;
        self.parse(&data).map_err(|detail| DsmError::Parse {
            api: self.api().into(),
            detail,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_matches_the_position_in_all() {
        for (i, e) in Endpoint::ALL.into_iter().enumerate() {
            assert_eq!(e.index(), i);
        }
    }

    #[test]
    fn default_intervals_match_the_spec() {
        assert_eq!(Endpoint::Utilization.default_interval().as_secs(), 5);
        assert_eq!(Endpoint::SystemInfo.default_interval().as_secs(), 30);
        assert_eq!(Endpoint::Storage.default_interval().as_secs(), 60);
        assert_eq!(Endpoint::Update.default_interval().as_secs(), 6 * 3600);
    }

    #[test]
    fn each_endpoint_names_its_api_and_method() {
        assert_eq!(
            (Endpoint::Storage.api(), Endpoint::Storage.method()),
            ("SYNO.Storage.CGI.Storage", "load_info")
        );
        assert_eq!(
            (Endpoint::Update.api(), Endpoint::Update.method()),
            ("SYNO.Core.Upgrade.Server", "check")
        );
    }
}
