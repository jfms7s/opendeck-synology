//! A scripted stand-in for a NAS, for tests. The handler sees each request
//! as a map of its form fields (plus `_path`) and answers like DSM would:
//! `Ok(data)` or `Err(error code)`.

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
        if req.get("api").map(String::as_str) == Some("SYNO.API.Info") {
            return Ok(Ok(api_info()));
        }
        Ok((self.handler)(&req))
    }
}

pub fn api_info() -> Value {
    let e = |max: u64| json!({ "maxVersion": max, "minVersion": 1, "path": "entry.cgi" });
    json!({
        "SYNO.API.Auth": e(7),
        "SYNO.Core.System.Utilization": e(1),
        "SYNO.Core.System": e(3),
        "SYNO.Storage.CGI.Storage": e(1),
        "SYNO.Core.Upgrade.Server": e(3),
    })
}
