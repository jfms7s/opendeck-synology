//! Which DSM web APIs we use, at which version, and where they live.
//! `SYNO.API.Info` tells us, since paths and versions vary between releases.

use crate::dsm::endpoint::Endpoint;
use crate::dsm::error::DsmError;
use crate::dsm::model::num;
use crate::dsm::transport::Transport;
use serde_json::Value;
use std::collections::HashMap;

/// The discovery API; its errors come before any login.
pub const INFO: &str = "SYNO.API.Info";
pub const AUTH: &str = "SYNO.API.Auth";
pub const UTILIZATION: &str = "SYNO.Core.System.Utilization";
pub const SYSTEM: &str = "SYNO.Core.System";
pub const STORAGE: &str = "SYNO.Storage.CGI.Storage";
pub const UPGRADE: &str = "SYNO.Core.Upgrade.Server";

/// The Auth version this plugin is written against.
const AUTH_VERSION: u64 = 6;

/// (api, version this plugin is written against): Auth plus one per data
/// endpoint. The version actually used is clamped into the range the NAS
/// offers.
pub fn wanted() -> Vec<(&'static str, u64)> {
    std::iter::once((AUTH, AUTH_VERSION))
        .chain(Endpoint::ALL.map(|e| (e.api(), e.version())))
        .collect()
}

/// Device tokens (2FA "remember this device") need Auth v6, i.e. DSM 7.
const MIN_AUTH_VERSION: u64 = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiInfo {
    pub path: String,
    pub version: u32,
}

pub type ApiMap = HashMap<String, ApiInfo>;

/// DSM sometimes sends API versions as strings; reject negative or
/// fractional values rather than silently truncating them.
fn version_num(v: &Value) -> Option<u64> {
    let n = num(v)?;
    if n.is_sign_negative() || n.fract() != 0.0 {
        return None;
    }
    Some(n as u64)
}

pub async fn discover(t: &dyn Transport) -> Result<ApiMap, DsmError> {
    let names = wanted()
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(",");
    let form = [
        ("api", INFO),
        ("version", "1"),
        ("method", "query"),
        ("query", names.as_str()),
    ];
    match t.call("query.cgi", &form).await? {
        Ok(data) => parse_api_info(&data),
        Err(code) => Err(DsmError::Api {
            api: INFO.into(),
            code,
        }),
    }
}

/// One API's (path, min, max), if the entry is usable: both versions
/// readable, `min <= max`, and small enough to send.
fn entry(e: &Value) -> Option<(&str, u64, u64)> {
    let path = e["path"].as_str()?;
    let (min, max) = (
        version_num(&e["minVersion"])?,
        version_num(&e["maxVersion"])?,
    );
    (min <= max && u32::try_from(max).is_ok()).then_some((path, min, max))
}

pub fn parse_api_info(data: &Value) -> Result<ApiMap, DsmError> {
    let mut map = ApiMap::new();
    for (name, wanted) in wanted() {
        let Some((path, min, max)) = entry(&data[name]) else {
            if name == AUTH {
                return Err(DsmError::Parse {
                    api: INFO.into(),
                    detail: "the NAS offers no usable SYNO.API.Auth".into(),
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
        let version = u32::try_from(wanted.clamp(min, max)).expect("max fits in u32, see entry()");
        map.insert(
            name.to_string(),
            ApiInfo {
                path: path.to_string(),
                version,
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
    fn versions_sent_as_strings_are_accepted() {
        let numeric = parse_api_info(&info()).unwrap();
        let mut v = info();
        v["SYNO.API.Auth"]["maxVersion"] = json!("7");
        v["SYNO.API.Auth"]["minVersion"] = json!("1");
        let map = parse_api_info(&v).unwrap();
        assert_eq!(map[AUTH].version, numeric[AUTH].version);
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
    fn an_inverted_version_range_is_treated_as_missing_not_a_panic() {
        let mut v = info();
        v[UTILIZATION]["minVersion"] = json!(3);
        v[UTILIZATION]["maxVersion"] = json!(1);
        let map = parse_api_info(&v).unwrap();
        assert!(!map.contains_key(UTILIZATION));
        let mut v = info();
        v[AUTH]["minVersion"] = json!(9);
        assert!(parse_api_info(&v).is_err(), "no usable SYNO.API.Auth");
    }

    #[test]
    fn a_version_beyond_u32_is_refused_rather_than_truncated() {
        let mut v = info();
        v[UTILIZATION]["minVersion"] = json!(4_294_967_297_u64);
        v[UTILIZATION]["maxVersion"] = json!(4_294_967_297_u64);
        assert!(!parse_api_info(&v).unwrap().contains_key(UTILIZATION));
    }

    /// The real `SYNO.API.Info` answer (see `model::tests::recorded`).
    #[test]
    fn recorded_api_info_offers_every_api() {
        let path = format!(
            "{}/tests/fixtures/real/api_info.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let Ok(raw) = std::fs::read_to_string(&path) else {
            assert!(
                std::env::var_os("REQUIRE_REAL_FIXTURES").is_none(),
                "{path} missing and REQUIRE_REAL_FIXTURES is set"
            );
            eprintln!("skipping: api_info.json not recorded");
            return;
        };
        let map = parse_api_info(&serde_json::from_str(&raw).unwrap()).unwrap();
        for (api, _) in wanted() {
            assert!(map.contains_key(api), "{api}");
        }
        assert!(map[AUTH].version >= 6);
    }

    #[test]
    fn the_fake_nas_offers_what_we_want() {
        let map = parse_api_info(&crate::dsm::fake::api_info()).unwrap();
        assert_eq!(map.len(), wanted().len());
    }
}
