//! DSM responses turned into plain domain types. DSM is loose with types
//! (sizes arrive as strings, percentages as strings or numbers), so parsing
//! walks `serde_json::Value` with small tolerant helpers rather than strict
//! serde structs: a firmware update that turns a number into a string must
//! not blank every key.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct Cpu {
    /// user + system + other load, 0-100.
    pub total_pct: f64,
    /// Load averages; `None` when DSM left one out (only that view is lost).
    pub load1: Option<f64>,
    pub load5: Option<f64>,
    pub load15: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Memory {
    pub used_pct: f64,
    pub total_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NetIf {
    /// `total` for the sum over all interfaces, else e.g. `eth0`.
    pub device: String,
    /// Bytes per second.
    pub rx: u64,
    pub tx: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Utilization {
    pub cpu: Cpu,
    pub memory: Memory,
    pub network: Vec<NetIf>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SystemInfo {
    pub sys_temp_c: Option<f64>,
    pub uptime_secs: Option<u64>,
    pub firmware: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Disk {
    /// Stable id such as `sata1` - survives drives being reordered.
    pub id: String,
    pub name: String,
    pub temp_c: Option<f64>,
    pub smart_status: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Volume {
    pub id: String,
    pub name: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Pool {
    pub id: String,
    pub name: String,
    pub status: String,
    /// Progress of a running repair/expansion/check, 0-100.
    pub progress_pct: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Storage {
    pub disks: Vec<Disk>,
    pub volumes: Vec<Volume>,
    pub pools: Vec<Pool>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpdateStatus {
    pub available: bool,
    pub version: Option<String>,
}

/// One poll result of any of the four endpoints.
#[derive(Debug, Clone, PartialEq)]
pub enum Payload {
    Utilization(Utilization),
    SystemInfo(SystemInfo),
    Storage(Storage),
    Update(UpdateStatus),
}

pub(crate) fn num(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn text(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string).filter(|s| !s.is_empty())
}

fn lower(v: &Value) -> String {
    text(v).unwrap_or_else(|| "unknown".into()).to_lowercase()
}

fn req_num(v: &Value, field: &str) -> Result<f64, String> {
    num(&v[field]).ok_or_else(|| format!("missing number `{field}`"))
}

/// "volume_1" -> "Volume 1"; an id without a trailing number stays as is.
fn numbered(prefix: &str, id: &str) -> String {
    match id.rsplit('_').next() {
        Some(n) if !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) => {
            format!("{prefix} {n}")
        }
        _ => id.to_string(),
    }
}

pub fn parse_utilization(data: &Value) -> Result<Utilization, String> {
    let c = &data["cpu"];
    // DSM reports load averages multiplied by 100 (a load of 0.42 arrives as 42).
    let cpu = Cpu {
        total_pct: req_num(c, "user_load")?
            + req_num(c, "system_load")?
            + num(&c["other_load"]).unwrap_or(0.0),
        load1: num(&c["1min_load"]).map(|l| l / 100.0),
        load5: num(&c["5min_load"]).map(|l| l / 100.0),
        load15: num(&c["15min_load"]).map(|l| l / 100.0),
    };
    let m = &data["memory"];
    // Memory sizes are in KiB.
    let total_kib = req_num(m, "total_real")?;
    // Page cache and buffers count as free, as in DSM's own `real_usage`.
    let free_kib = req_num(m, "avail_real")?
        + num(&m["buffer"]).unwrap_or(0.0)
        + num(&m["cached"]).unwrap_or(0.0);
    let memory = Memory {
        used_pct: req_num(m, "real_usage")?,
        total_bytes: (total_kib * 1024.0) as u64,
        used_bytes: ((total_kib - free_kib).max(0.0) * 1024.0) as u64,
    };
    let network = data["network"]
        .as_array()
        .map(|list| {
            list.iter()
                // An interface without both rates is left out (its key shows
                // "Missing"): a zero must never stand in for missing data.
                .filter_map(|n| {
                    Some(NetIf {
                        device: text(&n["device"])?,
                        rx: num(&n["rx"])? as u64,
                        tx: num(&n["tx"])? as u64,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Utilization {
        cpu,
        memory,
        network,
    })
}

/// `up_time` is "hours:minutes:seconds" with unbounded hours (e.g.
/// "293:05:11"); some firmware sends plain seconds instead.
fn parse_uptime(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    let parts: Vec<u64> = v
        .as_str()?
        .split(':')
        .map(|p| p.trim().parse().ok())
        .collect::<Option<_>>()?;
    match parts.as_slice() {
        [h, m, s] => Some(h * 3600 + m * 60 + s),
        [s] => Some(*s),
        _ => None,
    }
}

pub fn parse_system_info(data: &Value) -> Result<SystemInfo, String> {
    if !data.is_object() {
        return Err("expected an object".into());
    }
    Ok(SystemInfo {
        // Models without a system sensor report 0 or omit the field.
        sys_temp_c: num(&data["sys_temp"]).filter(|t| *t > 0.0),
        uptime_secs: parse_uptime(&data["up_time"]),
        firmware: text(&data["firmware_ver"]),
    })
}

pub fn parse_storage(data: &Value) -> Result<Storage, String> {
    if !data.is_object() {
        return Err("expected an object".into());
    }
    let list = |key: &str| data[key].as_array().map_or(&[][..], Vec::as_slice);
    let disks = list("disks")
        .iter()
        .filter_map(|d| {
            let id = text(&d["id"])?;
            Some(Disk {
                name: text(&d["longName"])
                    .or_else(|| text(&d["name"]))
                    .unwrap_or_else(|| id.clone()),
                // Drives without a sensor (some NVMe) report 0.
                temp_c: num(&d["temp"]).filter(|t| *t > 0.0),
                smart_status: lower(&d["smart_status"]),
                status: lower(&d["status"]),
                id,
            })
        })
        .collect();
    let volumes = list("volumes")
        .iter()
        .filter_map(|v| {
            let id = text(&v["id"])?;
            Some(Volume {
                name: numbered("Volume", &id),
                total_bytes: num(&v["size"]["total"])? as u64,
                used_bytes: num(&v["size"]["used"])? as u64,
                status: lower(&v["status"]),
                id,
            })
        })
        .collect();
    let pools = list("storagePools")
        .iter()
        .filter_map(|p| {
            let id = text(&p["id"])?;
            Some(Pool {
                name: numbered("Pool", &id),
                status: lower(&p["status"]),
                // -1 means "no operation running".
                progress_pct: num(&p["progress"]["percent"]).filter(|x| (0.0..=100.0).contains(x)),
                id,
            })
        })
        .collect();
    Ok(Storage {
        disks,
        volumes,
        pools,
    })
}

/// Most firmware nests the answer under `update`; accept both shapes.
pub fn parse_update(data: &Value) -> Result<UpdateStatus, String> {
    let u = if data["update"].is_object() {
        &data["update"]
    } else {
        data
    };
    let available = u["available"].as_bool().ok_or("missing `available`")?;
    Ok(UpdateStatus {
        available,
        version: if available { text(&u["version"]) } else { None },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsm::fake::fixture;
    use serde_json::{Value, json};

    /// DSM's `real_usage` counts page cache and buffers as free; used bytes
    /// must agree with it. Numbers recorded from a DS920+ on DSM 7.4.1.
    #[test]
    fn used_memory_leaves_out_cache_and_buffers() {
        let mut v = fixture("utilization.json");
        v["memory"] = json!({
            "total_real": 3_856_556, "avail_real": 143_596, "buffer": 11_648,
            "cached": 2_272_688, "real_usage": 37
        });
        let m = parse_utilization(&v).unwrap().memory;
        assert_eq!(m.used_bytes, 1_428_624 * 1024);
        let pct = m.used_bytes as f64 / m.total_bytes as f64 * 100.0;
        assert_eq!(pct.round(), m.used_pct);
    }

    #[test]
    fn parses_utilization() {
        let u = parse_utilization(&fixture("utilization.json")).unwrap();
        assert_eq!(u.cpu.total_pct, 37.0);
        assert_eq!(u.cpu.load1, Some(0.42));
        assert_eq!(u.cpu.load15, Some(0.35));
        assert_eq!(u.memory.used_pct, 37.0);
        assert_eq!(u.memory.total_bytes, 17_179_869_184);
        assert_eq!(u.memory.used_bytes, 6_442_450_944);
        assert_eq!(u.network.len(), 3);
        assert_eq!(
            u.network[0],
            NetIf {
                device: "total".into(),
                rx: 13_002_342,
                tx: 524_288
            }
        );
    }

    fn utilization_with(network: Value, cpu: Value) -> Value {
        let mut u = fixture("utilization.json");
        u["network"] = network;
        u["cpu"] = cpu;
        u
    }

    #[test]
    fn an_interface_without_rx_or_tx_is_skipped_not_zero() {
        let cpu = fixture("utilization.json")["cpu"].clone();
        let u = parse_utilization(&utilization_with(
            json!([
                { "device": "total", "rx": "100", "tx": 200 },
                { "device": "eth0", "tx": 5 },
                { "device": "eth1", "rx": 7, "tx": "n/a" }
            ]),
            cpu,
        ))
        .unwrap();
        assert_eq!(
            u.network,
            [NetIf {
                device: "total".into(),
                rx: 100,
                tx: 200
            }]
        );
    }

    #[test]
    fn a_missing_load_average_leaves_the_rest_of_the_payload() {
        let mut cpu = fixture("utilization.json")["cpu"].clone();
        cpu.as_object_mut().unwrap().remove("5min_load");
        let network = fixture("utilization.json")["network"].clone();
        let u = parse_utilization(&utilization_with(network, cpu)).unwrap();
        assert_eq!(u.cpu.total_pct, 37.0);
        assert_eq!((u.cpu.load1, u.cpu.load5), (Some(0.42), None));
        assert_eq!(u.memory.used_pct, 37.0);
        assert_eq!(u.network.len(), 3);
    }

    #[test]
    fn utilization_without_cpu_is_an_error() {
        assert!(parse_utilization(&json!({ "memory": {} })).is_err());
    }

    #[test]
    fn parses_system_info() {
        let s = parse_system_info(&fixture("system.json")).unwrap();
        assert_eq!(s.sys_temp_c, Some(48.0));
        assert_eq!(s.uptime_secs, Some(293 * 3600 + 5 * 60 + 11));
        assert_eq!(s.firmware.as_deref(), Some("DSM 7.2.2-72806 Update 3"));
    }

    #[test]
    fn missing_or_zero_system_temperature_is_none() {
        assert_eq!(
            parse_system_info(&json!({ "up_time": "1:00:00" }))
                .unwrap()
                .sys_temp_c,
            None
        );
        assert_eq!(
            parse_system_info(&json!({ "sys_temp": 0 }))
                .unwrap()
                .sys_temp_c,
            None
        );
    }

    #[test]
    fn uptime_accepts_plain_seconds() {
        let s = parse_system_info(&json!({ "up_time": 90061 })).unwrap();
        assert_eq!(s.uptime_secs, Some(90061));
    }

    #[test]
    fn parses_healthy_storage() {
        let s = parse_storage(&fixture("storage.json")).unwrap();
        assert_eq!(s.disks.len(), 3);
        assert_eq!(s.disks[0].id, "sata1");
        assert_eq!(s.disks[0].name, "Drive 1");
        assert_eq!(s.disks[1].temp_c, Some(44.0));
        assert_eq!(s.disks[2].temp_c, None, "NVMe without a sensor reports 0");
        assert_eq!(s.volumes[0].name, "Volume 1");
        assert_eq!(s.volumes[0].total_bytes, 7_680_000_000_000);
        assert_eq!(s.volumes[0].used_bytes, 5_452_800_000_000);
        assert_eq!(s.pools[0].name, "Pool 1");
        assert_eq!(s.pools[0].status, "normal");
        assert_eq!(
            s.pools[0].progress_pct, None,
            "-1 means no operation running"
        );
    }

    #[test]
    fn parses_degraded_storage() {
        let s = parse_storage(&fixture("storage_degraded.json")).unwrap();
        assert_eq!(s.disks[1].smart_status, "failing");
        assert_eq!(s.disks[1].status, "crashed");
        assert_eq!(s.pools[0].status, "degraded");
        assert_eq!(s.pools[1].status, "repairing");
        assert_eq!(s.pools[1].progress_pct, Some(43.0));
    }

    #[test]
    fn tolerates_numbers_and_strings() {
        let s = parse_storage(&json!({
            "disks": [{ "id": "sata1", "temp": "41", "smart_status": "Normal", "status": "normal" }],
            "volumes": [{ "id": "volume_2", "status": "normal", "size": { "total": 2000, "used": "500" } }],
            "storagePools": [{ "id": "reuse_3", "status": "expanding", "progress": { "percent": 12 } }]
        }))
        .unwrap();
        assert_eq!(s.disks[0].temp_c, Some(41.0));
        assert_eq!(
            s.disks[0].smart_status, "normal",
            "statuses are lower-cased"
        );
        assert_eq!(s.disks[0].name, "sata1", "falls back to the id");
        assert_eq!(s.volumes[0].total_bytes, 2000);
        assert_eq!(s.volumes[0].used_bytes, 500);
        assert_eq!(s.pools[0].progress_pct, Some(12.0));
    }

    #[test]
    fn entries_without_an_id_are_skipped() {
        let s =
            parse_storage(&json!({ "disks": [{ "temp": 30 }], "volumes": [], "storagePools": [] }))
                .unwrap();
        assert!(s.disks.is_empty());
    }

    #[test]
    fn parses_update_in_both_shapes() {
        let u = parse_update(&fixture("update.json")).unwrap();
        assert_eq!(
            u,
            UpdateStatus {
                available: true,
                version: Some("7.2.2-72806 Update 4".into())
            }
        );
        let none = parse_update(&json!({ "available": false, "version": "7.2.2" })).unwrap();
        assert_eq!(
            none,
            UpdateStatus {
                available: false,
                version: None
            }
        );
        assert!(parse_update(&json!({})).is_err());
    }

    #[test]
    fn parses_dsm7_shaped_alarm_states() {
        let s = parse_storage(&fixture("dsm7/storage_degraded.json")).unwrap();
        assert_eq!(
            (s.disks[1].smart_status.as_str(), s.disks[1].status.as_str()),
            ("failing", "crashed")
        );
        assert_eq!(s.pools[0].status, "degraded");
        assert_eq!(s.pools[0].progress_pct, None);
        assert_eq!(s.volumes[0].status, "degraded");
        assert_eq!(s.volumes[0].total_bytes, 3_839_999_999_999);
        let s = parse_storage(&fixture("dsm7/storage_repairing.json")).unwrap();
        assert_eq!(
            (s.pools[0].status.as_str(), s.pools[0].progress_pct),
            ("repairing", Some(43.0))
        );
        assert_eq!(
            (s.pools[1].status.as_str(), s.pools[1].progress_pct),
            ("data_scrubbing", Some(7.0))
        );
        assert_eq!(
            parse_update(&fixture("dsm7/update_available.json")).unwrap(),
            UpdateStatus {
                available: true,
                version: Some("DSM 7.4.2-80000".into())
            }
        );
        assert!(
            !parse_update(&fixture("dsm7/update_none.json"))
                .unwrap()
                .available
        );
    }

    /// Real responses from the author's NAS (`scripts/capture-fixtures.sh`,
    /// kept out of git). Skipped when not recorded, so CI and fresh clones
    /// pass - unless `REQUIRE_REAL_FIXTURES=1`, for a pre-release run on the
    /// machine that has them.
    fn recorded(name: &str) -> Option<Value> {
        let path = format!("{}/tests/fixtures/real/{name}", env!("CARGO_MANIFEST_DIR"));
        match std::fs::read_to_string(&path) {
            Ok(raw) => Some(serde_json::from_str(&raw).unwrap()),
            Err(_) if std::env::var_os("REQUIRE_REAL_FIXTURES").is_some() => {
                panic!("{path} missing and REQUIRE_REAL_FIXTURES is set")
            }
            Err(_) => {
                eprintln!("skipping {name}: not recorded");
                None
            }
        }
    }

    #[test]
    fn recorded_fixtures_parse_to_sensible_values() {
        if let Some(v) = recorded("utilization.json") {
            let u = parse_utilization(&v).unwrap();
            assert!((0.0..=100.0).contains(&u.cpu.total_pct), "{:?}", u.cpu);
            assert!(u.cpu.load1.is_some() && u.memory.total_bytes > 0);
            assert!(u.memory.used_bytes <= u.memory.total_bytes);
            assert!(u.network.iter().any(|n| n.device == "total"));
        }
        if let Some(v) = recorded("system.json") {
            let s = parse_system_info(&v).unwrap();
            assert!(s.uptime_secs.is_some_and(|t| t > 0));
            assert!(s.firmware.is_some_and(|f| f.contains("DSM")));
        }
        if let Some(v) = recorded("storage.json") {
            let s = parse_storage(&v).unwrap();
            assert!(!s.disks.is_empty() && !s.volumes.is_empty() && !s.pools.is_empty());
            assert!(s.disks.iter().all(|d| d.smart_status != "unknown"));
            assert!(
                s.volumes
                    .iter()
                    .all(|v| v.total_bytes > 0 && v.used_bytes <= v.total_bytes)
            );
            assert!(s.pools.iter().all(|p| p.status != "unknown"));
        }
        if let Some(v) = recorded("update.json") {
            parse_update(&v).unwrap();
        }
        if let Some(v) = recorded("login_keys.json") {
            let keys: Vec<String> = serde_json::from_value(v).unwrap();
            // `session::login` reads the device token from this field.
            assert!(keys.iter().any(|k| k == "did"), "{keys:?}");
            assert!(keys.iter().any(|k| k == "sid"), "{keys:?}");
        }
    }
}
