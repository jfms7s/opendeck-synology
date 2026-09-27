//! Which DSM web APIs we use, at which version, and where they live.
//! `SYNO.API.Info` tells us, since paths and versions vary between releases.

use crate::dsm::error::DsmError;
use crate::dsm::transport::Transport;
use serde_json::Value;
use std::collections::HashMap;

pub const AUTH: &str = "SYNO.API.Auth";
pub const UTILIZATION: &str = "SYNO.Core.System.Utilization";
pub const SYSTEM: &str = "SYNO.Core.System";
pub const STORAGE: &str = "SYNO.Storage.CGI.Storage";
pub const UPGRADE: &str = "SYNO.Core.Upgrade.Server";

/// (api, version this plugin is written against). The version actually used
/// is clamped into the range the NAS offers.
const WANTED: [(&str, u64); 5] = [
    (AUTH, 6),
    (UTILIZATION, 1),
    (SYSTEM, 1),
    (STORAGE, 1),
    (UPGRADE, 1),
];

/// Device tokens (2FA "remember this device") need Auth v6, i.e. DSM 7.
const MIN_AUTH_VERSION: u64 = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiInfo {
    pub path: String,
    pub version: u32,
}

pub type ApiMap = HashMap<String, ApiInfo>;

pub async fn discover(t: &dyn Transport) -> Result<ApiMap, DsmError> {
    let names = WANTED.map(|(name, _)| name).join(",");
    let form = [
        ("api", "SYNO.API.Info"),
        ("version", "1"),
        ("method", "query"),
        ("query", names.as_str()),
    ];
    match t.call("query.cgi", &form).await? {
        Ok(data) => parse_api_info(&data),
        Err(code) => Err(DsmError::Api {
            api: "SYNO.API.Info".into(),
            code,
        }),
    }
}

pub fn parse_api_info(data: &Value) -> Result<ApiMap, DsmError> {
    let mut map = ApiMap::new();
    for (name, wanted) in WANTED {
        let e = &data[name];
        let (Some(path), Some(min), Some(max)) = (
            e["path"].as_str(),
            e["minVersion"].as_u64(),
            e["maxVersion"].as_u64(),
        ) else {
            if name == AUTH {
                return Err(DsmError::Parse {
                    api: "SYNO.API.Info".into(),
                    detail: "the NAS offers no SYNO.API.Auth".into(),
                });
            }
            continue; // that endpoint's keys will show the error when polled
        };
        if name == AUTH && max < MIN_AUTH_VERSION {
            return Err(DsmError::Parse {
                api: AUTH.into(),
                detail: format!(
                    "needs DSM 7 (SYNO.API.Auth v{MIN_AUTH_VERSION}+), the NAS offers up to v{max}"
                ),
            });
        }
        map.insert(
            name.to_string(),
            ApiInfo {
                path: path.to_string(),
                version: wanted.clamp(min, max) as u32,
            },
        );
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn info() -> Value {
        json!({
            "SYNO.API.Auth": { "maxVersion": 7, "minVersion": 1, "path": "entry.cgi" },
            "SYNO.Core.System.Utilization": { "maxVersion": 1, "minVersion": 1, "path": "entry.cgi" },
            "SYNO.Core.System": { "maxVersion": 3, "minVersion": 1, "path": "entry.cgi" },
            "SYNO.Storage.CGI.Storage": { "maxVersion": 1, "minVersion": 1, "path": "entry.cgi" },
            "SYNO.Core.Upgrade.Server": { "maxVersion": 4, "minVersion": 2, "path": "entry.cgi" }
        })
    }

    #[test]
    fn picks_our_version_clamped_to_what_the_nas_offers() {
        let map = parse_api_info(&info()).unwrap();
        assert_eq!(
            map[AUTH],
            ApiInfo {
                path: "entry.cgi".into(),
                version: 6
            }
        );
        assert_eq!(map[SYSTEM].version, 1);
        assert_eq!(map[UPGRADE].version, 2, "raised to the NAS's minimum");
    }

    #[test]
    fn dsm_6_is_refused_with_a_clear_message() {
        let mut v = info();
        v["SYNO.API.Auth"]["maxVersion"] = json!(4);
        let err = parse_api_info(&v).unwrap_err();
        assert!(err.to_string().contains("DSM 7"), "{err}");
    }

    #[test]
    fn missing_optional_apis_are_skipped() {
        let mut v = info();
        v.as_object_mut().unwrap().remove(UPGRADE);
        let map = parse_api_info(&v).unwrap();
        assert!(!map.contains_key(UPGRADE));
        assert!(map.contains_key(AUTH));
    }

    #[test]
    fn recorded_api_info_parses() {
        let path = format!(
            "{}/tests/fixtures/real/api_info.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let Ok(raw) = std::fs::read_to_string(&path) else {
            eprintln!("skipping: api_info.json not recorded");
            return;
        };
        let map = parse_api_info(&serde_json::from_str(&raw).unwrap()).unwrap();
        assert!(map.contains_key(AUTH));
    }
}
