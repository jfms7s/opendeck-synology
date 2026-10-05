//! A scripted stand-in for a NAS, for tests. The handler sees each request
//! as a map of its form fields (plus `_path`) and answers like DSM would:
//! `Ok(data)` or `Err(error code)`.

use crate::dsm::api::{INFO, wanted};
use crate::dsm::error::DsmError;
use crate::dsm::transport::Transport;
use async_trait::async_trait;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub type Req = HashMap<String, String>;
type Handler = Box<dyn Fn(&Req) -> Result<Value, i64> + Send + Sync>;

pub struct FakeDsm {
    handler: Handler,
    log: Mutex<Vec<Req>>,
}

impl FakeDsm {
    pub fn new(handler: impl Fn(&Req) -> Result<Value, i64> + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self {
            handler: Box::new(handler),
            log: Mutex::new(Vec::new()),
        })
    }

    /// How many requests used this `method` (e.g. "login").
    pub fn count(&self, method: &str) -> usize {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.get("method").map(String::as_str) == Some(method))
            .count()
    }

    pub fn requests(&self) -> Vec<Req> {
        self.log.lock().unwrap().clone()
    }
}

#[async_trait]
impl Transport for FakeDsm {
    async fn call(
        &self,
        path: &str,
        form: &[(&str, &str)],
    ) -> Result<Result<Value, i64>, DsmError> {
        let mut req: Req = form
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        req.insert("_path".into(), path.into());
        self.log.lock().unwrap().push(req.clone());
        // Let concurrent callers interleave, like real network I/O would.
        tokio::task::yield_now().await;
        if req.get("api").map(String::as_str) == Some(INFO) {
            return Ok(Ok(api_info()));
        }
        Ok((self.handler)(&req))
    }
}

/// What a DSM 7 NAS answers to `SYNO.API.Info`: every API the plugin asks
/// for, offered from v1 up to one above the version it wants.
pub fn api_info() -> Value {
    wanted()
        .into_iter()
        .map(|(api, v)| {
            let e = json!({ "maxVersion": v + 1, "minVersion": 1, "path": "entry.cgi" });
            (api.to_string(), e)
        })
        .collect::<serde_json::Map<_, _>>()
        .into()
}

/// A JSON fixture from `tests/fixtures/`.
pub fn fixture(name: &str) -> Value {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// A NAS reached over a link that drops one kind of request: those
/// carrying form field `field` (e.g. a login with an `otp_code`).
pub struct Drops(pub Arc<dyn Transport>, pub &'static str);

#[async_trait]
impl Transport for Drops {
    async fn call(
        &self,
        path: &str,
        form: &[(&str, &str)],
    ) -> Result<Result<Value, i64>, DsmError> {
        if form.iter().any(|(k, _)| *k == self.1) {
            return Err(DsmError::Transport("connection reset".into()));
        }
        self.0.call(path, form).await
    }
}
