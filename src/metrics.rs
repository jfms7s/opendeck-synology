//! Turns the latest poll of an endpoint into what one key or dial shows.
//! Pure: no I/O and no clocks - everything it needs is passed in.

use crate::dsm::error::{AuthError, DsmError};
use crate::dsm::model::{
    Disk, Payload, Pool, Storage, SystemInfo, UpdateStatus, Utilization, Volume,
};
use crate::format;
use crate::metric::{Axis, Metric};
use crate::poller::PollState;
use crate::settings::{ActionSettings, Amount, CpuView, Direction, IoView, TempUnit};
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
const IO_VIEWS: [IoView; 4] = [IoView::Busy, IoView::Read, IoView::Write, IoView::Iops];

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
        ConnStatus::KeyringRefused(_) => ("Keyring", "Press to retry", Level::Error),
        ConnStatus::KeyringPending => ("Keyring", "Allow access", Level::Warn),
        ConnStatus::HttpsRequired => ("HTTPS", "Open settings", Level::Error),
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

fn as_utilization(p: &Payload) -> Option<&Utilization> {
    match p {
        Payload::Utilization(u) => Some(u),
        _ => None,
    }
}
fn as_system_info(p: &Payload) -> Option<&SystemInfo> {
    match p {
        Payload::SystemInfo(s) => Some(s),
        _ => None,
    }
}
fn as_storage(p: &Payload) -> Option<&Storage> {
    match p {
        Payload::Storage(s) => Some(s),
        _ => None,
    }
}
fn as_update(p: &Payload) -> Option<&UpdateStatus> {
    match p {
        Payload::Update(u) => Some(u),
        _ => None,
    }
}

/// Every metric has its own arm (no wildcard, so a new metric is a compile
/// error here); a payload from another endpoint reads "Error".
fn value_reading(metric: Metric, p: &Payload, v: &ActionSettings, unit: TempUnit) -> Reading {
    let reading = match metric {
        Metric::Cpu => as_utilization(p).map(|u| cpu(u, v)),
        Metric::Ram => as_utilization(p).map(|u| ram(u, v)),
        Metric::Network => as_utilization(p).map(|u| network(u, v)),
        Metric::StorageIo => as_utilization(p).map(|u| storage_io(u, v)),
        Metric::SysTemp => as_system_info(p).map(|s| sys_temp(s, v, unit)),
        Metric::DiskTemp => as_storage(p).map(|s| disk_temp(s, v, unit)),
        Metric::DiskHealth => as_storage(p).map(|s| disk_health(s, v)),
        Metric::Volume => as_storage(p).map(|s| volume(s, v)),
        Metric::Pool => as_storage(p).map(|s| pool(s, v)),
        Metric::Health => as_storage(p).map(|s| health(s, v, unit)),
        Metric::Update => as_update(p).map(update),
    };
    reading.unwrap_or_else(|| Reading::new(metric, "Error", Level::Error))
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
    let pager = (index_of(&CPU_VIEWS, &v.cpu_view), CPU_VIEWS.len());
    let subject = match v.cpu_view {
        CpuView::Total => "Usage",
        CpuView::Load1 => "Load 1 min",
        CpuView::Load5 => "Load 5 min",
        CpuView::Load15 => "Load 15 min",
    };
    // `u.cpu` is `None` when DSM's CPU block was unreadable: every view is lost.
    let Some(c) = &u.cpu else {
        return missing(Metric::Cpu, subject).pager(pager.0, pager.1);
    };
    let value = match v.cpu_view {
        CpuView::Total => Some(format::percent(c.total_pct)),
        CpuView::Load1 => c.load1.map(format::load),
        CpuView::Load5 => c.load5.map(format::load),
        CpuView::Load15 => c.load15.map(format::load),
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
    let pager = (index_of(&AMOUNTS, &v.amount), AMOUNTS.len());
    let Some(m) = &u.memory else {
        return missing(Metric::Ram, "Used").pager(pager.0, pager.1);
    };
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
    .pager(pager.0, pager.1)
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

/// Busy %, read or write rate, or IOPS of all disks, one disk or one
/// volume. The level and the bar follow busy % in every view: it is the
/// one 0-100 scale, and the thresholds are about it.
fn storage_io(u: &Utilization, v: &ActionSettings) -> Reading {
    let pager = (index_of(&IO_VIEWS, &v.io_view), IO_VIEWS.len());
    let io = &u.io;
    let stat = match v.target.as_deref() {
        None => io.all_disks.as_ref(),
        Some(id) => io.disks.iter().chain(&io.volumes).find(|s| s.id == id),
    };
    let Some(stat) = stat else {
        let what = v.target.as_deref().unwrap_or("All disks");
        return missing(Metric::StorageIo, what).pager(pager.0, pager.1);
    };
    let (value, what) = match v.io_view {
        IoView::Busy => (format::percent(stat.busy_pct), "busy"),
        IoView::Read => (format::rate(stat.read_bps), "read"),
        IoView::Write => (format::rate(stat.write_bps), "write"),
        IoView::Iops => (
            stat.read_iops.saturating_add(stat.write_iops).to_string(),
            "IOPS",
        ),
    };
    Reading::new(
        Metric::StorageIo,
        value,
        level_for(stat.busy_pct, thresholds(Metric::StorageIo, v)),
    )
    .subject(format!("{} {what}", stat.name))
    .bar(stat.busy_pct)
    .pager(pager.0, pager.1)
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
        // Problems only, worst first; with none there is nothing to turn to.
        Metric::Health => problems(s).into_iter().map(|p| Some(p.id)).collect(),
        // Their dial turns a view, not a storage target (`Fields::dial`).
        Metric::Cpu
        | Metric::Ram
        | Metric::Network
        | Metric::SysTemp
        | Metric::StorageIo
        | Metric::Update => Vec::new(),
    }
}

/// The target actually shown: for volumes and pools, unset means the first;
/// for the health summary, unset or no longer a problem means the worst.
fn resolved_target(metric: Metric, s: &Storage, v: &ActionSettings) -> Option<String> {
    match (metric, &v.target) {
        (Metric::Volume, None) => s.volumes.first().map(|x| x.id.clone()),
        (Metric::Pool, None) => s.pools.first().map(|x| x.id.clone()),
        (Metric::Health, t) => {
            let ids: Vec<String> = problems(s).into_iter().map(|p| p.id).collect();
            t.clone()
                .filter(|t| ids.contains(t))
                .or_else(|| ids.into_iter().next())
        }
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

/// `Normal`, `Degraded`, or what a running job is doing (`Rebuild 43%`).
fn pool_word(p: &Pool) -> String {
    let verb = match p.status.as_str() {
        "repairing" => "Rebuild".to_string(),
        "expanding" => "Expand".to_string(),
        "verifying" | "data_scrubbing" => "Check".to_string(),
        other => capitalize(other),
    };
    match (p.status.as_str(), p.progress_pct) {
        ("normal", _) => "Normal".to_string(),
        (_, Some(pct)) => format!("{verb} {pct:.0}%"),
        (_, None) => verb,
    }
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
    let r = Reading::new(Metric::Pool, pool_word(p), state_level(&p.status))
        .subject(p.name.clone())
        .pager(pos, count);
    match p.progress_pct {
        Some(pct) if p.status != "normal" => r.bar(pct),
        _ => r,
    }
}

/// One pool, disk or volume that needs attention, for the health summary.
/// `id` is namespaced by kind (`disk:sata2`, `pool:reuse_1`,
/// `volume:volume_1`), since the dial steps through all three kinds.
struct Problem {
    id: String,
    name: String,
    /// The value shown for it; temperatures are formatted when read.
    word: Word,
    level: Level,
}

enum Word {
    Text(String),
    Celsius(f64),
}

/// A disk: its health word, or, if healthy but at or over the Disk
/// Temperature warn default, its temperature in amber (never red: heat
/// alone is a warning, not a failure).
fn disk_problem(d: &Disk) -> Option<Problem> {
    let level = disk_level(d);
    let (word, level) = if level != Level::Normal {
        (Word::Text(health_word(level).to_string()), level)
    } else {
        let warn = thresholds(Metric::DiskTemp, &ActionSettings::default()).0;
        match d.temp_c {
            Some(c) if level_for(c, (warn, None)) == Level::Warn => (Word::Celsius(c), Level::Warn),
            _ => return None,
        }
    };
    Some(Problem {
        id: format!("disk:{}", d.id),
        name: d.name.clone(),
        word,
        level,
    })
}

fn pool_problem(p: &Pool) -> Option<Problem> {
    let level = state_level(&p.status);
    (level != Level::Normal).then(|| Problem {
        id: format!("pool:{}", p.id),
        name: p.name.clone(),
        word: Word::Text(pool_word(p)),
        level,
    })
}

/// A volume: its state word, or how full it is against the Volume
/// defaults (80/90 %). A volume without a size counts by state only.
fn volume_problem(x: &Volume) -> Option<Problem> {
    let state = state_level(&x.status);
    let (word, level) = if state != Level::Normal {
        (capitalize(&x.status), state)
    } else if x.total_bytes == 0 {
        return None;
    } else {
        let pct = x.used_bytes as f64 / x.total_bytes as f64 * 100.0;
        let level = level_for(pct, thresholds(Metric::Volume, &ActionSettings::default()));
        if level == Level::Normal {
            return None;
        }
        (format::percent(pct), level)
    };
    Some(Problem {
        id: format!("volume:{}", x.id),
        name: x.name.clone(),
        word: Word::Text(word),
        level,
    })
}

/// Everything that needs attention, worst first. Among equally bad items
/// disks come first (a failing drive is what degrades its pool and volume,
/// and what to act on), then pools, then volumes, each in DSM's order.
fn problems(s: &Storage) -> Vec<Problem> {
    let mut all: Vec<Problem> = s
        .disks
        .iter()
        .filter_map(disk_problem)
        .chain(s.pools.iter().filter_map(pool_problem))
        .chain(s.volumes.iter().filter_map(volume_problem))
        .collect();
    // Stable, so the kind order above breaks ties.
    all.sort_by_key(|p| std::cmp::Reverse(p.level));
    all
}

fn count(n: usize, one: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {one}s")
    }
}

/// One key for every pool, disk and volume: `OK` with the counts, or the
/// worst item. A dial turned to another problem shows that one, but the
/// colour stays the worst level, so the key never under-reports.
fn health(s: &Storage, v: &ActionSettings, unit: TempUnit) -> Reading {
    let (pos, of) = position(Metric::Health, s, v);
    let all = problems(s);
    let Some(worst) = all.first().map(|p| p.level) else {
        if s.disks.is_empty() && s.pools.is_empty() && s.volumes.is_empty() {
            return Reading::new(Metric::Health, "N/A", Level::Normal).subject("No storage");
        }
        let subject = format!(
            "{} · {} · {}",
            count(s.pools.len(), "pool"),
            count(s.disks.len(), "disk"),
            count(s.volumes.len(), "volume")
        );
        return Reading::new(Metric::Health, "OK", Level::Normal).subject(subject);
    };
    let shown = &all[pos];
    let value = match shown.word {
        Word::Text(ref t) => t.clone(),
        Word::Celsius(c) => format::temperature(c, unit),
    };
    Reading::new(Metric::Health, value, worst)
        .subject(shown.name.clone())
        .pager(pos, of)
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
/// Which setting it turns is the catalogue's `Fields::dial`.
pub fn rotate(metric: Metric, view: &mut ActionSettings, latest: Option<&Payload>, ticks: i16) {
    let Some(axis) = metric.fields().dial else {
        return;
    };
    match axis {
        Axis::CpuView => {
            view.cpu_view =
                CPU_VIEWS[step(index_of(&CPU_VIEWS, &view.cpu_view), CPU_VIEWS.len(), ticks)]
        }
        Axis::Amount => {
            view.amount = AMOUNTS[step(index_of(&AMOUNTS, &view.amount), AMOUNTS.len(), ticks)]
        }
        Axis::Direction => {
            view.direction = DIRECTIONS[step(
                index_of(&DIRECTIONS, &view.direction),
                DIRECTIONS.len(),
                ticks,
            )]
        }
        Axis::IoView => {
            view.io_view = IO_VIEWS[step(index_of(&IO_VIEWS, &view.io_view), IO_VIEWS.len(), ticks)]
        }
        Axis::Target | Axis::Problem => {
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
    let options = match metric {
        Metric::Network => as_utilization(p).map(|u| {
            std::iter::once((None, "All interfaces".to_string()))
                .chain(
                    u.network
                        .iter()
                        .filter(|n| n.device != "total")
                        .map(|n| (Some(n.device.clone()), n.device.clone())),
                )
                .collect()
        }),
        Metric::StorageIo => as_utilization(p).map(|u| {
            std::iter::once((None, "All disks".to_string()))
                .chain(
                    u.io.disks
                        .iter()
                        .chain(&u.io.volumes)
                        .map(|x| (Some(x.id.clone()), x.name.clone())),
                )
                .collect()
        }),
        Metric::DiskTemp => as_storage(p).map(|s| disks(s, "Hottest disk")),
        Metric::DiskHealth => as_storage(p).map(|s| disks(s, "Worst disk")),
        Metric::Volume => as_storage(p).map(|s| {
            s.volumes
                .iter()
                .map(|x| (Some(x.id.clone()), x.name.clone()))
                .collect()
        }),
        Metric::Pool => as_storage(p).map(|s| {
            s.pools
                .iter()
                .map(|x| (Some(x.id.clone()), x.name.clone()))
                .collect()
        }),
        // No `target` field (`Fields::target`): no dropdown.
        Metric::Cpu | Metric::Ram | Metric::SysTemp | Metric::Health | Metric::Update => None,
    };
    options.unwrap_or_default()
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

    /// The fixture payload of each endpoint.
    fn fixture_for(e: crate::metric::Endpoint) -> Payload {
        use crate::metric::Endpoint;
        match e {
            Endpoint::Utilization => util(),
            Endpoint::SystemInfo => system(fixture("system.json")),
            Endpoint::Storage => storage("storage.json"),
            Endpoint::Update => Payload::Update(parse_update(&fixture("update.json")).unwrap()),
        }
    }

    /// Each metric's reading, dial axis, dropdown and manifest `Rotate`
    /// text agree, so adding or changing one can't leave the others behind.
    #[test]
    fn every_metric_agrees_with_its_catalogue_entry() {
        let manifest: Value =
            serde_json::from_str(include_str!("../assets/manifest.json")).unwrap();
        for metric in Metric::ALL {
            let p = fixture_for(metric.endpoint());
            let fields = metric.fields();
            let r = read_as(metric, p.clone(), &view());
            assert_ne!(r.value, "Error", "{metric:?} reads its own endpoint");
            let action = manifest["Actions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|a| a["UUID"] == metric.uuid())
                .unwrap();
            let rotate_text = &action["Encoder"]["TriggerDescription"]["Rotate"];
            assert_eq!(
                fields.dial.is_some(),
                rotate_text.is_string(),
                "{metric:?}: a dial axis exactly when the manifest describes Rotate"
            );
            if fields.dial == Some(Axis::Target) {
                assert!(fields.target.is_some(), "{metric:?} turns a target it has");
            }
            assert_eq!(
                fields.target.is_some(),
                !target_options(metric, &p).is_empty(),
                "{metric:?}: a target field exactly when it has dropdown options"
            );
            // The dial does something with the fixture.
            if fields.dial.is_some() && fields.dial != Some(Axis::Problem) {
                let mut turned = view();
                rotate(metric, &mut turned, Some(&p), 1);
                assert_ne!(turned, view(), "{metric:?}'s dial changed nothing");
            }
        }
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
        u.cpu.as_mut().unwrap().load5 = None;
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
    fn an_unreadable_memory_block_shows_missing_on_ram_only() {
        let mut v = fixture("utilization.json");
        v.as_object_mut().unwrap().remove("memory");
        let p = || Payload::Utilization(parse_utilization(&v).unwrap());
        let r = read_as(Metric::Ram, p(), &view());
        assert_eq!(
            (r.value.as_str(), r.subject.as_str(), r.level, r.pager),
            ("Missing", "Used", Level::Crit, Some((0, 2)))
        );
        assert_eq!(read_as(Metric::Cpu, p(), &view()).value, "37%");
        assert_eq!(
            read_as(Metric::Network, p(), &view()).value,
            read_as(Metric::Network, util(), &view()).value
        );
    }

    #[test]
    fn an_unreadable_cpu_field_shows_missing_on_cpu_only() {
        let mut v = fixture("utilization.json");
        v["cpu"].as_object_mut().unwrap().remove("system_load");
        let p = || Payload::Utilization(parse_utilization(&v).unwrap());
        let r = read_as(Metric::Cpu, p(), &view());
        assert_eq!(
            (r.value.as_str(), r.subject.as_str(), r.level, r.pager),
            ("Missing", "Usage", Level::Crit, Some((0, 4)))
        );
        assert_eq!(read_as(Metric::Ram, p(), &view()).value, "37%");
        assert_eq!(
            read_as(Metric::Network, p(), &view()).value,
            read_as(Metric::Network, util(), &view()).value
        );
    }

    fn io() -> Payload {
        Payload::Utilization(parse_utilization(&fixture("dsm7/utilization_io.json")).unwrap())
    }

    fn io_as(target: Option<&str>, io_view: IoView) -> Reading {
        let v = ActionSettings {
            target: target.map(str::to_string),
            io_view,
            ..view()
        };
        read_as(Metric::StorageIo, io(), &v)
    }

    #[test]
    fn storage_io_views_of_all_disks() {
        let r = io_as(None, IoView::Busy);
        assert_eq!(
            (r.title, r.value.as_str(), r.subject.as_str()),
            ("I/O", "45%", "All disks busy")
        );
        assert_eq!(
            (r.level, r.bar, r.pager),
            (Level::Normal, Some(45.0), Some((0, 4)))
        );
        let r = io_as(None, IoView::Read);
        assert_eq!(
            (r.value.as_str(), r.subject.as_str(), r.pager),
            ("50.0 MB/s", "All disks read", Some((1, 4)))
        );
        assert_eq!(io_as(None, IoView::Write).value, "10.0 MB/s");
        let r = io_as(None, IoView::Iops);
        assert_eq!(
            (r.value.as_str(), r.subject.as_str()),
            ("400", "All disks IOPS")
        );
        assert_eq!(r.bar, Some(45.0), "the bar is busy % in every view");
    }

    #[test]
    fn storage_io_of_one_disk_or_volume() {
        let r = io_as(Some("sata1"), IoView::Busy);
        assert_eq!(
            (r.value.as_str(), r.subject.as_str()),
            ("82%", "Drive 1 busy")
        );
        assert_eq!(r.level, Level::Warn);
        let r = io_as(Some("volume1"), IoView::Read);
        assert_eq!(
            (r.value.as_str(), r.subject.as_str()),
            ("50.0 MB/s", "Volume 1 read")
        );
        assert_eq!(r.level, Level::Crit, "96 % busy colours every view");
    }

    #[test]
    fn storage_io_busy_thresholds() {
        let mut u = parse_utilization(&fixture("dsm7/utilization_io.json")).unwrap();
        for (busy, want) in [
            (79.0, Level::Normal),
            (80.0, Level::Warn),
            (94.9, Level::Warn),
            (95.0, Level::Crit),
        ] {
            u.io.all_disks.as_mut().unwrap().busy_pct = busy;
            let r = read_as(Metric::StorageIo, Payload::Utilization(u.clone()), &view());
            assert_eq!(r.level, want, "{busy}");
        }
        let v = ActionSettings {
            warn: Some(40.0),
            crit: Some(99.0),
            ..view()
        };
        assert_eq!(read_as(Metric::StorageIo, io(), &v).level, Level::Warn);
    }

    #[test]
    fn storage_io_of_an_unknown_or_unreadable_target_is_missing() {
        let r = io_as(Some("sata9"), IoView::Read);
        assert_eq!(
            (r.value.as_str(), r.subject.as_str(), r.level, r.pager),
            ("Missing", "sata9", Level::Crit, Some((1, 4)))
        );
        assert_eq!(io_as(Some("nvme0n1"), IoView::Busy).value, "Missing");
        // A NAS whose reply has no I/O blocks: missing, never a zero.
        let r = read_as(Metric::StorageIo, util(), &view());
        assert_eq!(
            (r.value.as_str(), r.subject.as_str()),
            ("Missing", "All disks")
        );
    }

    #[test]
    fn storage_io_targets_and_rotation() {
        let opts = target_options(Metric::StorageIo, &io());
        assert_eq!(
            opts,
            [
                (None, "All disks".to_string()),
                (Some("sata1".to_string()), "Drive 1".to_string()),
                (Some("sata2".to_string()), "Drive 2".to_string()),
                (Some("volume1".to_string()), "Volume 1".to_string()),
            ]
        );
        let mut v = view();
        rotate(Metric::StorageIo, &mut v, Some(&io()), 1);
        assert_eq!(v.io_view, IoView::Read);
        rotate(Metric::StorageIo, &mut v, None, -2);
        assert_eq!(v.io_view, IoView::Iops);
        assert_eq!(v.target, None, "turning changes the view, not the target");
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
    fn a_refused_keyring_tells_every_key_to_press_to_retry() {
        let status = ConnStatus::KeyringRefused("denied".into());
        let ctx = Context {
            status: &status,
            unit: TempUnit::Celsius,
        };
        let r = read(Metric::Cpu, &state(util()), &view(), &ctx);
        assert_eq!((r.value.as_str(), r.level), ("Keyring", Level::Error));
        assert_eq!(r.subject, "Press to retry");
    }

    #[test]
    fn a_saved_http_connection_shows_https_required_on_every_key() {
        let status = ConnStatus::HttpsRequired;
        let ctx = Context {
            status: &status,
            unit: TempUnit::Celsius,
        };
        let r = read(Metric::Cpu, &state(util()), &view(), &ctx);
        assert_eq!((r.value.as_str(), r.level), ("HTTPS", Level::Error));
        assert_eq!(r.subject, "Open settings");
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
        assert!(target_options(Metric::Health, &storage("storage.json")).is_empty());
    }

    fn storage_of(name: &str) -> Storage {
        let Payload::Storage(s) = storage(name) else {
            unreachable!()
        };
        s
    }
    fn health(s: Storage, v: &ActionSettings) -> Reading {
        read_as(Metric::Health, Payload::Storage(s), v)
    }
    fn shown(r: &Reading) -> (&str, &str, Level) {
        (r.value.as_str(), r.subject.as_str(), r.level)
    }

    #[test]
    fn health_all_well_counts_pools_disks_and_volumes() {
        let r = health(storage_of("storage.json"), &view());
        assert_eq!(r.title, "NAS");
        assert_eq!(
            shown(&r),
            ("OK", "1 pool · 3 disks · 1 volume", Level::Normal)
        );
        assert_eq!((r.bar, r.pager), (None, None));
        let mut s = storage_of("dsm7/storage_repairing.json");
        s.pools.iter_mut().for_each(|p| p.status = "normal".into());
        assert_eq!(health(s, &view()).subject, "2 pools · 2 disks · 1 volume");
        let r = health(Storage::default(), &view());
        assert_eq!(shown(&r), ("N/A", "No storage", Level::Normal));
    }

    #[test]
    fn health_names_a_degraded_pool() {
        let mut s = storage_of("storage.json");
        s.pools[0].status = "degraded".into();
        assert_eq!(
            shown(&health(s, &view())),
            ("Degraded", "Pool 1", Level::Crit)
        );
    }

    #[test]
    fn health_names_a_failing_disk_first() {
        // Drive 2 is failing, which also degrades its pool and volume: the
        // disk is the one to act on, so it is named.
        let r = health(storage_of("dsm7/storage_degraded.json"), &view());
        assert_eq!(shown(&r), ("Failing", "Drive 2", Level::Crit));
        assert_eq!(r.pager, Some((0, 3)));
    }

    #[test]
    fn health_shows_a_repairing_pool_in_amber() {
        let r = health(storage_of("dsm7/storage_repairing.json"), &view());
        assert_eq!(shown(&r), ("Rebuild 43%", "Pool 1", Level::Warn));
        assert_eq!(r.pager, Some((0, 2)));
    }

    #[test]
    fn health_unknown_state_words_are_a_warning() {
        let mut s = storage_of("storage.json");
        s.volumes[0].status = "something_new".into();
        assert_eq!(
            shown(&health(s, &view())),
            ("Something_new", "Volume 1", Level::Warn)
        );
    }

    #[test]
    fn health_counts_a_full_volume_at_the_volume_thresholds() {
        let mut s = storage_of("storage.json");
        s.volumes[0].used_bytes = s.volumes[0].total_bytes / 100 * 95;
        assert_eq!(
            shown(&health(s.clone(), &view())),
            ("95%", "Volume 1", Level::Crit)
        );
        s.volumes[0].used_bytes = s.volumes[0].total_bytes / 100 * 85;
        assert_eq!(
            shown(&health(s.clone(), &view())),
            ("85%", "Volume 1", Level::Warn)
        );
        // No size: never a zero, and only the state word counts.
        s.volumes[0].total_bytes = 0;
        assert_eq!(health(s, &view()).value, "OK");
    }

    #[test]
    fn health_counts_a_hot_disk_as_amber_only() {
        let mut s = storage_of("storage.json");
        s.disks[1].temp_c = Some(52.0);
        assert_eq!(
            shown(&health(s.clone(), &view())),
            ("52°C", "Drive 2", Level::Warn)
        );
        s.disks[1].temp_c = Some(65.0);
        assert_eq!(health(s.clone(), &view()).level, Level::Warn);
        s.disks[1].temp_c = Some(49.0);
        assert_eq!(health(s, &view()).value, "OK");
    }

    #[test]
    fn health_names_the_worst_item_whatever_its_kind() {
        let mut s = storage_of("storage.json");
        s.disks[0].temp_c = Some(55.0);
        s.volumes[0].status = "crashed".into();
        let r = health(s, &view());
        assert_eq!(shown(&r), ("Crashed", "Volume 1", Level::Crit));
        assert_eq!(r.pager, Some((0, 2)));
    }

    #[test]
    fn health_key_colour_stays_the_worst_while_the_dial_shows_a_lesser_item() {
        let mut s = storage_of("dsm7/storage_repairing.json");
        s.disks[0].smart_status = "failing".into();
        let v = ActionSettings {
            target: Some("pool:reuse_2".into()),
            ..view()
        };
        let r = health(s, &v);
        assert_eq!(shown(&r), ("Check 7%", "Pool 2", Level::Crit));
        assert_eq!(r.pager, Some((2, 3)));
    }

    #[test]
    fn health_target_that_is_no_longer_a_problem_falls_back_to_the_summary() {
        let v = ActionSettings {
            target: Some("pool:reuse_1".into()),
            ..view()
        };
        assert_eq!(health(storage_of("storage.json"), &v).value, "OK");
        let v = ActionSettings {
            target: Some("disk:sata1".into()),
            ..view()
        };
        let r = health(storage_of("dsm7/storage_degraded.json"), &v);
        assert_eq!((r.subject.as_str(), r.pager), ("Drive 2", Some((0, 3))));
    }

    #[test]
    fn health_rotation_walks_only_problems_and_wraps() {
        let p = storage("dsm7/storage_degraded.json");
        let mut v = view();
        rotate(Metric::Health, &mut v, Some(&p), 1);
        assert_eq!(v.target.as_deref(), Some("pool:reuse_1"));
        rotate(Metric::Health, &mut v, Some(&p), 1);
        assert_eq!(v.target.as_deref(), Some("volume:volume_1"));
        let r = read_as(Metric::Health, p.clone(), &v);
        assert_eq!(shown(&r), ("Degraded", "Volume 1", Level::Crit));
        rotate(Metric::Health, &mut v, Some(&p), 1);
        assert_eq!(v.target.as_deref(), Some("disk:sata2"));
        rotate(Metric::Health, &mut v, Some(&p), -1);
        assert_eq!(v.target.as_deref(), Some("volume:volume_1"));

        let well = storage("storage.json");
        let mut v = view();
        rotate(Metric::Health, &mut v, Some(&well), 1);
        assert_eq!(v.target, None, "all well: the dial does not move");
        rotate(Metric::Health, &mut v, None, 1);
        assert_eq!(v.target, None, "no data yet: nothing to rotate through");
    }
}
