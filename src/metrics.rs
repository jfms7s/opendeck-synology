//! Turns the latest poll of an endpoint into what one key or dial shows.
//! Pure: no I/O and no clocks - everything it needs is passed in.

use crate::dsm::error::{AuthError, DsmError};
use crate::dsm::model::{Disk, Payload, Storage, SystemInfo, UpdateStatus, Utilization};
use crate::format;
use crate::metric::Metric;
use crate::poller::PollState;
use crate::settings::{ActionSettings, Amount, CpuView, Direction, TempUnit};
use crate::status::ConnStatus;
use std::cmp::Ordering;

/// Consecutive failed polls before a still-shown value is marked stale.
pub const STALE_AFTER: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Normal,
    Warn,
    Crit,
    Stale,
    Error,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Reading {
    pub title: &'static str,
    pub value: String,
    pub subject: String,
    pub level: Level,
    /// 0-100 fill for the dial's bar; `None` draws a full bar in the level's colour.
    pub bar: Option<f64>,
    /// (position, count) when turning the dial has somewhere to go.
    pub pager: Option<(usize, usize)>,
}

impl Reading {
    fn new(metric: Metric, value: impl Into<String>, level: Level) -> Self {
        Self {
            title: metric.title(),
            value: value.into(),
            subject: String::new(),
            level,
            bar: None,
            pager: None,
        }
    }
    fn subject(mut self, s: impl Into<String>) -> Self {
        self.subject = s.into();
        self
    }
    fn bar(mut self, pct: f64) -> Self {
        self.bar = Some(pct.clamp(0.0, 100.0));
        self
    }
    fn pager(mut self, pos: usize, count: usize) -> Self {
        if count > 1 {
            self.pager = Some((pos, count));
        }
        self
    }
}

pub struct Context<'a> {
    pub status: &'a ConnStatus,
    pub unit: TempUnit,
}

const CPU_VIEWS: [CpuView; 4] = [
    CpuView::Total,
    CpuView::Load1,
    CpuView::Load5,
    CpuView::Load15,
];
const AMOUNTS: [Amount; 2] = [Amount::Percent, Amount::Used];
const DIRECTIONS: [Direction; 3] = [Direction::In, Direction::Out, Direction::Combined];

pub fn read(
    metric: Metric,
    state: &PollState<Payload>,
    view: &ActionSettings,
    ctx: &Context,
) -> Reading {
    if let Some(r) = connection_reading(metric, ctx.status) {
        return r;
    }
    match (&state.value, &state.error) {
        (_, Some(e)) if e.needs_user() => error_reading(metric, e),
        (None, Some(e)) => error_reading(metric, e),
        (None, None) => Reading::new(metric, "…", Level::Normal),
        (Some(p), _) => {
            let mut r = value_reading(metric, p, view, ctx.unit);
            if state.failures >= STALE_AFTER {
                r.level = Level::Stale;
            }
            r
        }
    }
}

/// When the connection itself needs the user, every key says so.
fn connection_reading(metric: Metric, status: &ConnStatus) -> Option<Reading> {
    let (value, subject, level) = match status {
        ConnStatus::NotConfigured => ("Set up", "Open settings", Level::Normal),
        ConnStatus::Auth(AuthError::NeedOtp | AuthError::BadOtp) => {
            ("2FA", "Enter code", Level::Warn)
        }
        ConnStatus::Auth(_) => ("Login", "Check settings", Level::Error),
        ConnStatus::Certificate { .. } => ("Cert", "Check settings", Level::Error),
        ConnStatus::Keyring(_) => ("Keyring", "Open settings", Level::Error),
        ConnStatus::KeyringPending => ("Keyring", "Allow access", Level::Warn),
        ConnStatus::Connecting | ConnStatus::Connected { .. } | ConnStatus::Unreachable(_) => {
            return None;
        }
    };
    Some(Reading::new(metric, value, level).subject(subject))
}

/// A poll's error. One about the connection (credentials, certificate,
/// settings) reads exactly like the connection status it implies; only
/// errors about this endpoint have their own wording.
fn error_reading(metric: Metric, e: &DsmError) -> Reading {
    if let Some(r) = ConnStatus::from_error(e).and_then(|s| connection_reading(metric, &s)) {
        return r;
    }
    let (value, subject) = match e {
        DsmError::Permission { .. } => ("Denied", "No permission".to_string()),
        DsmError::Api { code, .. } => ("Error", format!("DSM {code}")),
        DsmError::Parse { .. } => ("Error", "Bad data".to_string()),
        // Transport, and anything connection-level not drawn above.
        _ => ("Offline", String::new()),
    };
    Reading::new(metric, value, Level::Error).subject(subject)
}

fn value_reading(metric: Metric, p: &Payload, v: &ActionSettings, unit: TempUnit) -> Reading {
    match (metric, p) {
        (Metric::Cpu, Payload::Utilization(u)) => cpu(u, v),
        (Metric::Ram, Payload::Utilization(u)) => ram(u, v),
        (Metric::Network, Payload::Utilization(u)) => network(u, v),
        (Metric::SysTemp, Payload::SystemInfo(s)) => sys_temp(s, v, unit),
        (Metric::Uptime, Payload::SystemInfo(s)) => uptime(s),
        (Metric::DiskTemp, Payload::Storage(s)) => disk_temp(s, v, unit),
        (Metric::DiskHealth, Payload::Storage(s)) => disk_health(s, v),
        (Metric::Volume, Payload::Storage(s)) => volume(s, v),
        (Metric::Pool, Payload::Storage(s)) => pool(s, v),
        (Metric::Update, Payload::Update(u)) => update(u),
        _ => Reading::new(metric, "Error", Level::Error),
    }
}

fn thresholds(metric: Metric, v: &ActionSettings) -> (Option<f64>, Option<f64>) {
    let d = metric.default_thresholds();
    (v.warn.or(d.map(|t| t.0)), v.crit.or(d.map(|t| t.1)))
}

fn level_for(value: f64, (warn, crit): (Option<f64>, Option<f64>)) -> Level {
    if crit.is_some_and(|c| value >= c) {
        Level::Crit
    } else if warn.is_some_and(|w| value >= w) {
        Level::Warn
    } else {
        Level::Normal
    }
}

fn index_of<T: PartialEq>(list: &[T], x: &T) -> usize {
    list.iter().position(|y| y == x).unwrap_or(0)
}

fn missing(metric: Metric, what: &str) -> Reading {
    Reading::new(metric, "Missing", Level::Crit).subject(what)
}

fn cpu(u: &Utilization, v: &ActionSettings) -> Reading {
    let c = &u.cpu;
    let pager = (index_of(&CPU_VIEWS, &v.cpu_view), CPU_VIEWS.len());
    let (value, subject) = match v.cpu_view {
        CpuView::Total => (Some(format::percent(c.total_pct)), "Usage"),
        CpuView::Load1 => (c.load1.map(format::load), "Load 1 min"),
        CpuView::Load5 => (c.load5.map(format::load), "Load 5 min"),
        CpuView::Load15 => (c.load15.map(format::load), "Load 15 min"),
    };
    let Some(value) = value else {
        return missing(Metric::Cpu, subject).pager(pager.0, pager.1);
    };
    let r = Reading::new(Metric::Cpu, value, Level::Normal)
        .subject(subject)
        .pager(pager.0, pager.1);
    // The thresholds and the bar are about CPU %; a load average has no
    // 0-100 scale, so the load views show the number alone.
    match v.cpu_view {
        CpuView::Total => Reading {
            level: level_for(c.total_pct, thresholds(Metric::Cpu, v)),
            ..r
        }
        .bar(c.total_pct),
        CpuView::Load1 | CpuView::Load5 | CpuView::Load15 => r,
    }
}

fn ram(u: &Utilization, v: &ActionSettings) -> Reading {
    let m = &u.memory;
    let value = match v.amount {
        Amount::Percent => format::percent(m.used_pct),
        Amount::Used => format::used_of_total(m.used_bytes, m.total_bytes),
    };
    Reading::new(
        Metric::Ram,
        value,
        level_for(m.used_pct, thresholds(Metric::Ram, v)),
    )
    .subject("Used")
    .bar(m.used_pct)
    .pager(index_of(&AMOUNTS, &v.amount), AMOUNTS.len())
}

fn network(u: &Utilization, v: &ActionSettings) -> Reading {
    let device = v.target.as_deref().unwrap_or("total");
    let Some(nic) = u.network.iter().find(|n| n.device == device) else {
        return missing(Metric::Network, device);
    };
    let (bps, arrow) = match v.direction {
        Direction::In => (nic.rx, "↓"),
        Direction::Out => (nic.tx, "↑"),
        Direction::Combined => (nic.rx.saturating_add(nic.tx), "↕"),
    };
    let mbps = bps as f64 / 1_048_576.0;
    let subject = if device == "total" {
        "All interfaces"
    } else {
        device
    };
    let r = Reading::new(
        Metric::Network,
        format!("{arrow}{}", format::rate(bps)),
        level_for(mbps, (v.warn, v.crit)),
    )
    .subject(subject)
    .pager(index_of(&DIRECTIONS, &v.direction), DIRECTIONS.len());
    match v.crit.filter(|c| *c > 0.0) {
        Some(crit) => r.bar(mbps / crit * 100.0),
        None => r,
    }
}

fn sys_temp(s: &SystemInfo, v: &ActionSettings, unit: TempUnit) -> Reading {
    let Some(c) = s.sys_temp_c else {
        return Reading::new(Metric::SysTemp, "N/A", Level::Normal).subject("No sensor");
    };
    Reading::new(
        Metric::SysTemp,
        format::temperature(c, unit),
        level_for(c, thresholds(Metric::SysTemp, v)),
    )
    .subject("Temperature")
    .bar(c)
}

fn uptime(s: &SystemInfo) -> Reading {
    match s.uptime_secs {
        Some(secs) => Reading::new(Metric::Uptime, format::uptime(secs), Level::Normal),
        None => Reading::new(Metric::Uptime, "N/A", Level::Normal),
    }
}

/// What turning the dial steps through, `None` being the aggregate entry
/// (hottest/worst disk). Volumes and pools have no aggregate.
fn rotation_targets(metric: Metric, s: &Storage) -> Vec<Option<String>> {
    match metric {
        Metric::DiskTemp | Metric::DiskHealth => s
            .disks
            .iter()
            .map(|d| Some(d.id.clone()))
            .chain([None])
            .collect(),
        Metric::Volume => s.volumes.iter().map(|x| Some(x.id.clone())).collect(),
        Metric::Pool => s.pools.iter().map(|x| Some(x.id.clone())).collect(),
        _ => Vec::new(),
    }
}

/// The target actually shown: for volumes and pools, unset means the first.
fn resolved_target(metric: Metric, s: &Storage, v: &ActionSettings) -> Option<String> {
    match (metric, &v.target) {
        (Metric::Volume, None) => s.volumes.first().map(|x| x.id.clone()),
        (Metric::Pool, None) => s.pools.first().map(|x| x.id.clone()),
        (_, t) => t.clone(),
    }
}

fn position(metric: Metric, s: &Storage, v: &ActionSettings) -> (usize, usize) {
    let cycle = rotation_targets(metric, s);
    (
        index_of(&cycle, &resolved_target(metric, s, v)),
        cycle.len(),
    )
}

fn disk_temp(s: &Storage, v: &ActionSettings, unit: TempUnit) -> Reading {
    let (pos, count) = position(Metric::DiskTemp, s, v);
    let (disk, subject) = match v.target.as_deref() {
        Some(id) => match s.disks.iter().find(|d| d.id == id) {
            Some(d) => (Some(d), d.name.clone()),
            None => return missing(Metric::DiskTemp, id),
        },
        None => {
            let hottest = s
                .disks
                .iter()
                .filter(|d| d.temp_c.is_some())
                .max_by(|a, b| a.temp_c.partial_cmp(&b.temp_c).unwrap_or(Ordering::Equal));
            let subject = hottest.map_or_else(
                || "No sensors".to_string(),
                |d| format!("Hottest: {}", d.name),
            );
            (hottest, subject)
        }
    };
    let Some(c) = disk.and_then(|d| d.temp_c) else {
        return Reading::new(Metric::DiskTemp, "N/A", Level::Normal)
            .subject(subject)
            .pager(pos, count);
    };
    Reading::new(
        Metric::DiskTemp,
        format::temperature(c, unit),
        level_for(c, thresholds(Metric::DiskTemp, v)),
    )
    .subject(subject)
    .bar(c)
    .pager(pos, count)
}

/// Worst of the S.M.A.R.T. verdict and the drive's own status. Unknown
/// words count as a warning: better a false alarm than a silent failure.
fn disk_level(d: &Disk) -> Level {
    let smart = match d.smart_status.as_str() {
        "normal" => Level::Normal,
        "failing" | "crashed" | "damage" => Level::Crit,
        _ => Level::Warn,
    };
    let status = match d.status.as_str() {
        "normal" | "initialized" | "not_initialized" => Level::Normal,
        "crashed" | "failing" | "system_partition_failed" => Level::Crit,
        _ => Level::Warn,
    };
    smart.max(status)
}

fn health_word(level: Level) -> &'static str {
    match level {
        Level::Normal => "OK",
        Level::Warn => "Warning",
        _ => "Failing",
    }
}

fn disk_health(s: &Storage, v: &ActionSettings) -> Reading {
    let (pos, count) = position(Metric::DiskHealth, s, v);
    let (level, subject) = match v.target.as_deref() {
        Some(id) => match s.disks.iter().find(|d| d.id == id) {
            Some(d) => (disk_level(d), d.name.clone()),
            None => return missing(Metric::DiskHealth, id),
        },
        // `rev` so that among equally bad disks the first one is named.
        None => match s.disks.iter().rev().max_by_key(|d| disk_level(d)) {
            None => {
                return Reading::new(Metric::DiskHealth, "N/A", Level::Normal).subject("No disks");
            }
            Some(d) if disk_level(d) == Level::Normal => {
                (Level::Normal, format!("All {} disks", s.disks.len()))
            }
            Some(d) => (disk_level(d), d.name.clone()),
        },
    };
    Reading::new(Metric::DiskHealth, health_word(level), level)
        .subject(subject)
        .pager(pos, count)
}

/// Volume and pool states share DSM's vocabulary.
fn state_level(status: &str) -> Level {
    match status {
        "normal" => Level::Normal,
        "degraded" | "crashed" => Level::Crit,
        _ => Level::Warn,
    }
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    chars
        .next()
        .map_or_else(String::new, |c| c.to_uppercase().chain(chars).collect())
}

fn volume(s: &Storage, v: &ActionSettings) -> Reading {
    let (pos, count) = position(Metric::Volume, s, v);
    let vol = match v.target.as_deref() {
        Some(id) => match s.volumes.iter().find(|x| x.id == id) {
            Some(x) => x,
            None => return missing(Metric::Volume, id),
        },
        None => match s.volumes.first() {
            Some(x) => x,
            None => {
                return Reading::new(Metric::Volume, "N/A", Level::Normal).subject("No volumes");
            }
        },
    };
    // No size yet (a volume being created, a crashed one): a zero must never
    // stand in for missing data.
    if vol.total_bytes == 0 {
        let subject = format!("{} · {}", vol.name, capitalize(&vol.status));
        return Reading::new(Metric::Volume, "N/A", state_level(&vol.status))
            .subject(subject)
            .pager(pos, count);
    }
    let pct = vol.used_bytes as f64 / vol.total_bytes as f64 * 100.0;
    let value = match v.amount {
        Amount::Percent => format::percent(pct),
        Amount::Used => format::used_of_total(vol.used_bytes, vol.total_bytes),
    };
    let level = level_for(pct, thresholds(Metric::Volume, v)).max(state_level(&vol.status));
    Reading::new(Metric::Volume, value, level)
        .subject(vol.name.clone())
        .bar(pct)
        .pager(pos, count)
}

fn pool(s: &Storage, v: &ActionSettings) -> Reading {
    let (pos, count) = position(Metric::Pool, s, v);
    let p = match v.target.as_deref() {
        Some(id) => match s.pools.iter().find(|x| x.id == id) {
            Some(x) => x,
            None => return missing(Metric::Pool, id),
        },
        None => match s.pools.first() {
            Some(x) => x,
            None => return Reading::new(Metric::Pool, "N/A", Level::Normal).subject("No pools"),
        },
    };
    let verb = match p.status.as_str() {
        "repairing" => "Rebuild".to_string(),
        "expanding" => "Expand".to_string(),
        "verifying" | "data_scrubbing" => "Check".to_string(),
        other => capitalize(other),
    };
    let value = match (p.status.as_str(), p.progress_pct) {
        ("normal", _) => "Normal".to_string(),
        (_, Some(pct)) => format!("{verb} {pct:.0}%"),
        (_, None) => verb,
    };
    let r = Reading::new(Metric::Pool, value, state_level(&p.status))
        .subject(p.name.clone())
        .pager(pos, count);
    match p.progress_pct {
        Some(pct) if p.status != "normal" => r.bar(pct),
        _ => r,
    }
}

fn update(u: &UpdateStatus) -> Reading {
    if u.available {
        Reading::new(Metric::Update, "Update", Level::Warn)
            .subject(u.version.clone().unwrap_or_default())
    } else {
        Reading::new(Metric::Update, "Up to date", Level::Normal)
    }
}

fn step(i: usize, n: usize, ticks: i16) -> usize {
    (i as i64 + i64::from(ticks)).rem_euclid(n as i64) as usize
}

/// Applies a dial turn to an instance's in-memory view, wrapping at the ends.
pub fn rotate(metric: Metric, view: &mut ActionSettings, latest: Option<&Payload>, ticks: i16) {
    match metric {
        Metric::Cpu => {
            view.cpu_view =
                CPU_VIEWS[step(index_of(&CPU_VIEWS, &view.cpu_view), CPU_VIEWS.len(), ticks)]
        }
        Metric::Ram => {
            view.amount = AMOUNTS[step(index_of(&AMOUNTS, &view.amount), AMOUNTS.len(), ticks)]
        }
        Metric::Network => {
            view.direction = DIRECTIONS[step(
                index_of(&DIRECTIONS, &view.direction),
                DIRECTIONS.len(),
                ticks,
            )]
        }
        Metric::DiskTemp | Metric::DiskHealth | Metric::Volume | Metric::Pool => {
            let Some(Payload::Storage(s)) = latest else {
                return;
            };
            let cycle = rotation_targets(metric, s);
            if cycle.is_empty() {
                return;
            }
            let i = index_of(&cycle, &resolved_target(metric, s, view));
            view.target = cycle[step(i, cycle.len(), ticks)].clone();
        }
        Metric::SysTemp | Metric::Uptime | Metric::Update => {}
    }
}

/// Choices for the settings panel's target dropdown: (setting value, label),
/// a `None` value meaning the aggregate.
pub fn target_options(metric: Metric, p: &Payload) -> Vec<(Option<String>, String)> {
    let disks = |s: &Storage, aggregate: &str| -> Vec<(Option<String>, String)> {
        std::iter::once((None, aggregate.to_string()))
            .chain(s.disks.iter().map(|d| (Some(d.id.clone()), d.name.clone())))
            .collect()
    };
    match (metric, p) {
        (Metric::Network, Payload::Utilization(u)) => {
            std::iter::once((None, "All interfaces".to_string()))
                .chain(
                    u.network
                        .iter()
                        .filter(|n| n.device != "total")
                        .map(|n| (Some(n.device.clone()), n.device.clone())),
                )
                .collect()
        }
        (Metric::DiskTemp, Payload::Storage(s)) => disks(s, "Hottest disk"),
        (Metric::DiskHealth, Payload::Storage(s)) => disks(s, "Worst disk"),
        (Metric::Volume, Payload::Storage(s)) => s
            .volumes
            .iter()
            .map(|x| (Some(x.id.clone()), x.name.clone()))
            .collect(),
        (Metric::Pool, Payload::Storage(s)) => s
            .pools
            .iter()
            .map(|x| (Some(x.id.clone()), x.name.clone()))
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsm::fake::fixture;
    use crate::dsm::model::{parse_storage, parse_system_info, parse_update, parse_utilization};
    use serde_json::{Value, json};
    use std::sync::Arc;

    fn util() -> Payload {
        Payload::Utilization(parse_utilization(&fixture("utilization.json")).unwrap())
    }
    fn storage(name: &str) -> Payload {
        Payload::Storage(parse_storage(&fixture(name)).unwrap())
    }
    fn system(v: Value) -> Payload {
        Payload::SystemInfo(parse_system_info(&v).unwrap())
    }
    fn state(p: Payload) -> PollState<Payload> {
        PollState {
            value: Some(Arc::new(p)),
            error: None,
            failures: 0,
        }
    }
    fn connected() -> ConnStatus {
        ConnStatus::Connected {
            account: "jf".into(),
        }
    }
    fn read_as(metric: Metric, p: Payload, view: &ActionSettings) -> Reading {
        let status = connected();
        read(
            metric,
            &state(p),
            view,
            &Context {
                status: &status,
                unit: TempUnit::Celsius,
            },
        )
    }
    fn view() -> ActionSettings {
        ActionSettings::default()
    }

    #[test]
    fn cpu_total_and_load_views() {
        let r = read_as(Metric::Cpu, util(), &view());
        assert_eq!(
            (r.title, r.value.as_str(), r.subject.as_str()),
            ("CPU", "37%", "Usage")
        );
        assert_eq!(
            (r.level, r.bar, r.pager),
            (Level::Normal, Some(37.0), Some((0, 4)))
        );
        let v = ActionSettings {
            cpu_view: CpuView::Load1,
            ..view()
        };
        let r = read_as(Metric::Cpu, util(), &v);
        assert_eq!(
            (r.value.as_str(), r.subject.as_str(), r.pager),
            ("0.42", "Load 1 min", Some((1, 4)))
        );
    }

    #[test]
    fn a_load_view_is_not_coloured_by_cpu_percent() {
        // 37 % is over a 10 % warn threshold, but the key shows a load
        // average, which the % thresholds don't apply to.
        let v = ActionSettings {
            cpu_view: CpuView::Load5,
            warn: Some(10.0),
            ..view()
        };
        let r = read_as(Metric::Cpu, util(), &v);
        assert_eq!(
            (r.value.as_str(), r.level, r.bar),
            ("0.38", Level::Normal, None)
        );
    }

    #[test]
    fn a_missing_load_average_shows_missing_on_that_view_only() {
        let Payload::Utilization(mut u) = util() else {
            unreachable!()
        };
        u.cpu.load5 = None;
        let v = ActionSettings {
            cpu_view: CpuView::Load5,
            ..view()
        };
        let r = read_as(Metric::Cpu, Payload::Utilization(u.clone()), &v);
        assert_eq!(
            (r.value.as_str(), r.subject.as_str(), r.level, r.pager),
            ("Missing", "Load 5 min", Level::Crit, Some((2, 4)))
        );
        let r = read_as(Metric::Cpu, Payload::Utilization(u), &view());
        assert_eq!(r.value, "37%");
    }

    #[test]
    fn thresholds_default_per_metric_and_can_be_overridden() {
        assert_eq!(read_as(Metric::Cpu, util(), &view()).level, Level::Normal);
        let v = ActionSettings {
            warn: Some(30.0),
            ..view()
        };
        assert_eq!(read_as(Metric::Cpu, util(), &v).level, Level::Warn);
        let v = ActionSettings {
            warn: Some(10.0),
            crit: Some(35.0),
            ..view()
        };
        assert_eq!(read_as(Metric::Cpu, util(), &v).level, Level::Crit);
    }

    #[test]
    fn ram_shows_percent_or_used_of_total() {
        let r = read_as(Metric::Ram, util(), &view());
        assert_eq!((r.value.as_str(), r.pager), ("37%", Some((0, 2))));
        let v = ActionSettings {
            amount: Amount::Used,
            ..view()
        };
        assert_eq!(read_as(Metric::Ram, util(), &v).value, "6.0/16 GB");
    }

    #[test]
    fn network_directions_and_interfaces() {
        let r = read_as(Metric::Network, util(), &view());
        assert_eq!(
            (r.value.as_str(), r.subject.as_str()),
            ("↓12.4 MB/s", "All interfaces")
        );
        assert_eq!(
            (r.level, r.bar),
            (Level::Normal, None),
            "no thresholds unless set"
        );
        let v = ActionSettings {
            direction: Direction::Out,
            target: Some("eth1".into()),
            ..view()
        };
        let r = read_as(Metric::Network, util(), &v);
        assert_eq!(
            (r.value.as_str(), r.subject.as_str(), r.pager),
            ("↑4.2 KB/s", "eth1", Some((1, 3)))
        );
        let v = ActionSettings {
            target: Some("bond0".into()),
            ..view()
        };
        let r = read_as(Metric::Network, util(), &v);
        assert_eq!((r.value.as_str(), r.level), ("Missing", Level::Crit));
    }

    #[test]
    fn network_thresholds_are_in_megabytes_per_second() {
        let v = ActionSettings {
            warn: Some(5.0),
            crit: Some(10.0),
            ..view()
        };
        let r = read_as(Metric::Network, util(), &v);
        assert_eq!((r.level, r.bar), (Level::Crit, Some(100.0)));
    }

    #[test]
    fn system_temperature_and_missing_sensor() {
        let r = read_as(Metric::SysTemp, system(fixture("system.json")), &view());
        assert_eq!((r.value.as_str(), r.level), ("48°C", Level::Normal));
        let r = read_as(
            Metric::SysTemp,
            system(json!({ "up_time": "1:0:0" })),
            &view(),
        );
        assert_eq!((r.value.as_str(), r.level), ("N/A", Level::Normal));
        let status = connected();
        let ctx = Context {
            status: &status,
            unit: TempUnit::Fahrenheit,
        };
        let r = read(
            Metric::SysTemp,
            &state(system(fixture("system.json"))),
            &view(),
            &ctx,
        );
        assert_eq!(r.value, "118°F");
    }

    #[test]
    fn uptime_is_formatted() {
        let r = read_as(Metric::Uptime, system(fixture("system.json")), &view());
        assert_eq!(r.value, "12d 5h");
    }

    #[test]
    fn disk_temperature_hottest_specific_missing_and_sensorless() {
        let r = read_as(Metric::DiskTemp, storage("storage.json"), &view());
        assert_eq!(
            (r.value.as_str(), r.subject.as_str(), r.pager),
            ("44°C", "Hottest: Drive 2", Some((3, 4)))
        );
        let v = ActionSettings {
            target: Some("sata1".into()),
            ..view()
        };
        let r = read_as(Metric::DiskTemp, storage("storage.json"), &v);
        assert_eq!(
            (r.value.as_str(), r.subject.as_str(), r.pager),
            ("38°C", "Drive 1", Some((0, 4)))
        );
        let v = ActionSettings {
            target: Some("nvme0n1".into()),
            ..view()
        };
        assert_eq!(
            read_as(Metric::DiskTemp, storage("storage.json"), &v).value,
            "N/A"
        );
        let v = ActionSettings {
            target: Some("sata9".into()),
            ..view()
        };
        let r = read_as(Metric::DiskTemp, storage("storage.json"), &v);
        assert_eq!((r.value.as_str(), r.level), ("Missing", Level::Crit));
        let r = read_as(Metric::DiskTemp, storage("storage_degraded.json"), &view());
        assert_eq!(r.level, Level::Crit, "61 °C is over the 60 °C default");
    }

    #[test]
    fn disk_health_worst_and_specific() {
        let r = read_as(Metric::DiskHealth, storage("storage.json"), &view());
        assert_eq!(
            (r.value.as_str(), r.subject.as_str(), r.level),
            ("OK", "All 3 disks", Level::Normal)
        );
        let r = read_as(
            Metric::DiskHealth,
            storage("storage_degraded.json"),
            &view(),
        );
        assert_eq!(
            (r.value.as_str(), r.subject.as_str(), r.level),
            ("Failing", "Drive 2", Level::Crit)
        );
        let v = ActionSettings {
            target: Some("sata1".into()),
            ..view()
        };
        assert_eq!(
            read_as(Metric::DiskHealth, storage("storage_degraded.json"), &v).value,
            "OK"
        );
    }

    #[test]
    fn volume_percent_used_and_status() {
        let r = read_as(Metric::Volume, storage("storage.json"), &view());
        assert_eq!(
            (r.value.as_str(), r.subject.as_str(), r.level),
            ("71%", "Volume 1", Level::Normal)
        );
        let v = ActionSettings {
            amount: Amount::Used,
            ..view()
        };
        assert_eq!(
            read_as(Metric::Volume, storage("storage.json"), &v).value,
            "5.0/7.0 TB"
        );
        let Payload::Storage(mut s) = storage("storage.json") else {
            unreachable!()
        };
        s.volumes[0].status = "degraded".into();
        assert_eq!(
            read_as(Metric::Volume, Payload::Storage(s), &view()).level,
            Level::Crit
        );
    }

    #[test]
    fn a_volume_without_a_size_shows_na_not_zero() {
        let Payload::Storage(mut s) = storage("storage.json") else {
            unreachable!()
        };
        s.volumes[0].total_bytes = 0;
        s.volumes[0].status = "creating".into();
        let r = read_as(Metric::Volume, Payload::Storage(s), &view());
        assert_eq!(
            (r.value.as_str(), r.subject.as_str(), r.level, r.bar),
            ("N/A", "Volume 1 · Creating", Level::Warn, None)
        );
    }

    fn disk(id: &str, smart: &str, status: &str) -> Disk {
        Disk {
            id: id.into(),
            name: format!("Drive {id}"),
            temp_c: None,
            smart_status: smart.into(),
            status: status.into(),
        }
    }

    #[test]
    fn unknown_disk_words_are_a_warning_not_ok() {
        assert_eq!(
            disk_level(&disk("1", "something_new", "normal")),
            Level::Warn
        );
        assert_eq!(
            disk_level(&disk("1", "normal", "something_new")),
            Level::Warn
        );
        assert_eq!(
            disk_level(&disk("1", "normal", "initialized")),
            Level::Normal
        );
        assert_eq!(disk_level(&disk("1", "damage", "normal")), Level::Crit);
        assert_eq!(
            disk_level(&disk("1", "normal", "system_partition_failed")),
            Level::Crit
        );
    }

    #[test]
    fn among_equally_bad_disks_the_first_is_named() {
        let s = Storage {
            disks: vec![
                disk("1", "normal", "normal"),
                disk("2", "failing", "normal"),
                disk("3", "failing", "normal"),
            ],
            ..Storage::default()
        };
        let r = read_as(Metric::DiskHealth, Payload::Storage(s), &view());
        assert_eq!(
            (r.value.as_str(), r.subject.as_str()),
            ("Failing", "Drive 2")
        );
    }

    #[test]
    fn pool_states() {
        let r = read_as(Metric::Pool, storage("storage.json"), &view());
        assert_eq!(
            (r.value.as_str(), r.subject.as_str(), r.level, r.bar),
            ("Normal", "Pool 1", Level::Normal, None)
        );
        let r = read_as(Metric::Pool, storage("storage_degraded.json"), &view());
        assert_eq!(
            (r.value.as_str(), r.level, r.pager),
            ("Degraded", Level::Crit, Some((0, 2)))
        );
        let v = ActionSettings {
            target: Some("reuse_2".into()),
            ..view()
        };
        let r = read_as(Metric::Pool, storage("storage_degraded.json"), &v);
        assert_eq!(
            (r.value.as_str(), r.level, r.bar),
            ("Rebuild 43%", Level::Warn, Some(43.0))
        );
    }

    #[test]
    fn dsm7_shaped_alarm_states_reach_the_keys() {
        let degraded = || storage("dsm7/storage_degraded.json");
        let r = read_as(Metric::DiskHealth, degraded(), &view());
        assert_eq!(
            (r.value.as_str(), r.subject.as_str(), r.level),
            ("Failing", "Drive 2", Level::Crit)
        );
        let r = read_as(Metric::Pool, degraded(), &view());
        assert_eq!(
            (r.value.as_str(), r.level, r.bar),
            ("Degraded", Level::Crit, None)
        );
        assert_eq!(
            read_as(Metric::Volume, degraded(), &view()).level,
            Level::Crit
        );
        let repairing = || storage("dsm7/storage_repairing.json");
        let r = read_as(Metric::Pool, repairing(), &view());
        assert_eq!(
            (r.value.as_str(), r.level, r.bar),
            ("Rebuild 43%", Level::Warn, Some(43.0))
        );
        let v = ActionSettings {
            target: Some("reuse_2".into()),
            ..view()
        };
        let r = read_as(Metric::Pool, repairing(), &v);
        assert_eq!((r.value.as_str(), r.level), ("Check 7%", Level::Warn));
        let p = Payload::Update(parse_update(&fixture("dsm7/update_available.json")).unwrap());
        let r = read_as(Metric::Update, p, &view());
        assert_eq!(
            (r.value.as_str(), r.subject.as_str(), r.level),
            ("Update", "DSM 7.4.2-80000", Level::Warn)
        );
    }

    #[test]
    fn update_available_or_not() {
        let p = Payload::Update(parse_update(&fixture("update.json")).unwrap());
        let r = read_as(Metric::Update, p, &view());
        assert_eq!(
            (r.value.as_str(), r.subject.as_str(), r.level),
            ("Update", "7.2.2-72806 Update 4", Level::Warn)
        );
        let p = Payload::Update(parse_update(&json!({ "available": false })).unwrap());
        assert_eq!(read_as(Metric::Update, p, &view()).value, "Up to date");
    }

    #[test]
    fn goes_stale_after_three_failures_but_keeps_the_value() {
        let status = connected();
        let ctx = Context {
            status: &status,
            unit: TempUnit::Celsius,
        };
        let mut st = state(util());
        st.error = Some(DsmError::Transport("down".into()));
        st.failures = 2;
        assert_eq!(read(Metric::Cpu, &st, &view(), &ctx).level, Level::Normal);
        st.failures = STALE_AFTER;
        let r = read(Metric::Cpu, &st, &view(), &ctx);
        assert_eq!((r.value.as_str(), r.level), ("37%", Level::Stale));
    }

    #[test]
    fn placeholders_and_errors_without_a_value() {
        let status = connected();
        let ctx = Context {
            status: &status,
            unit: TempUnit::Celsius,
        };
        let r = read(Metric::Cpu, &PollState::default(), &view(), &ctx);
        assert_eq!(r.value, "…");
        let st = PollState {
            value: None,
            error: Some(DsmError::Transport("x".into())),
            failures: 1,
        };
        assert_eq!(read(Metric::Cpu, &st, &view(), &ctx).value, "Offline");
        let st = PollState {
            value: None,
            error: Some(DsmError::Permission { api: "x".into() }),
            failures: 1,
        };
        let r = read(Metric::Volume, &st, &view(), &ctx);
        assert_eq!(
            (r.value.as_str(), r.subject.as_str(), r.level),
            ("Denied", "No permission", Level::Error)
        );
    }

    #[test]
    fn an_endpoint_error_about_the_connection_reads_like_the_connection_status() {
        let status = connected();
        let ctx = Context {
            status: &status,
            unit: TempUnit::Celsius,
        };
        // E.g. the poller saw "2FA needed" a moment before the status did.
        for (e, want) in [
            (DsmError::Auth(AuthError::NeedOtp), ("2FA", Level::Warn)),
            (
                DsmError::Auth(AuthError::BadCredentials),
                ("Login", Level::Error),
            ),
            (DsmError::NotConfigured, ("Set up", Level::Normal)),
        ] {
            let st = PollState {
                value: None,
                error: Some(e.clone()),
                failures: 1,
            };
            let r = read(Metric::Cpu, &st, &view(), &ctx);
            assert_eq!(
                (r.value.as_str(), r.level),
                want,
                "{e:?} must match connection_reading"
            );
            let as_status = ConnStatus::from_error(&e).unwrap();
            let r2 = connection_reading(Metric::Cpu, &as_status).unwrap();
            assert_eq!(r, r2);
        }
    }

    #[test]
    fn an_unreadable_keyring_shows_on_every_key() {
        let status = ConnStatus::Keyring("locked".into());
        let ctx = Context {
            status: &status,
            unit: TempUnit::Celsius,
        };
        let r = read(Metric::Cpu, &state(util()), &view(), &ctx);
        assert_eq!((r.value.as_str(), r.level), ("Keyring", Level::Error));
    }

    #[test]
    fn a_pending_keyring_prompt_shows_on_every_key() {
        let status = ConnStatus::KeyringPending;
        let ctx = Context {
            status: &status,
            unit: TempUnit::Celsius,
        };
        let r = read(Metric::Cpu, &state(util()), &view(), &ctx);
        assert_eq!((r.value.as_str(), r.level), ("Keyring", Level::Warn));
        assert_eq!(r.subject, "Allow access");
    }

    #[test]
    fn connection_problems_override_values() {
        let status = ConnStatus::Auth(AuthError::NeedOtp);
        let ctx = Context {
            status: &status,
            unit: TempUnit::Celsius,
        };
        let r = read(Metric::Cpu, &state(util()), &view(), &ctx);
        assert_eq!((r.value.as_str(), r.level), ("2FA", Level::Warn));
        let status = ConnStatus::NotConfigured;
        let ctx = Context {
            status: &status,
            unit: TempUnit::Celsius,
        };
        assert_eq!(
            read(Metric::Cpu, &PollState::default(), &view(), &ctx).value,
            "Set up"
        );
    }

    #[test]
    fn rotation_cycles_views_with_wraparound() {
        let mut v = view();
        rotate(Metric::Cpu, &mut v, None, -1);
        assert_eq!(v.cpu_view, CpuView::Load15);
        rotate(Metric::Cpu, &mut v, None, 2);
        assert_eq!(v.cpu_view, CpuView::Load1);
        rotate(Metric::Network, &mut v, None, 1);
        assert_eq!(v.direction, Direction::Out);
        rotate(Metric::Ram, &mut v, None, 1);
        assert_eq!(v.amount, Amount::Used);
    }

    #[test]
    fn rotation_steps_through_disks_then_the_aggregate() {
        let p = storage("storage.json");
        let mut v = view();
        rotate(Metric::DiskTemp, &mut v, Some(&p), 1);
        assert_eq!(v.target.as_deref(), Some("sata1"));
        rotate(Metric::DiskTemp, &mut v, Some(&p), -1);
        assert_eq!(v.target, None);
        rotate(Metric::DiskTemp, &mut v, Some(&p), -1);
        assert_eq!(v.target.as_deref(), Some("nvme0n1"));
        let mut v = view();
        rotate(Metric::DiskTemp, &mut v, None, 1);
        assert_eq!(v.target, None, "no data yet: nothing to rotate through");
    }

    #[test]
    fn rotation_through_pools_starts_from_the_first() {
        let p = storage("storage_degraded.json");
        let mut v = view();
        rotate(Metric::Pool, &mut v, Some(&p), 1);
        assert_eq!(v.target.as_deref(), Some("reuse_2"));
    }

    #[test]
    fn target_options_for_the_settings_panel() {
        let opts = target_options(Metric::DiskHealth, &storage("storage.json"));
        assert_eq!(opts[0], (None, "Worst disk".to_string()));
        assert_eq!(opts[1], (Some("sata1".into()), "Drive 1".to_string()));
        let opts = target_options(Metric::Network, &util());
        assert_eq!(opts.len(), 3, "all interfaces + eth0 + eth1, not `total`");
        assert!(target_options(Metric::Cpu, &util()).is_empty());
    }
}
