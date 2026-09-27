//! The wire: POST a form to `/webapi/<path>` and unwrap DSM's
//! `{success, data | error}` envelope. Every parameter goes in the POST
//! body, so the password, 2FA code and session id never appear in a URL,
//! a proxy log or an error message.

use crate::dsm::error::DsmError;
use crate::dsm::tls::{PinningVerifier, Rejection};
use crate::settings::Connection;
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(10);

#[async_trait]
pub trait Transport: Send + Sync {
    /// `Ok(Ok(data))` on success, `Ok(Err(code))` when DSM answered with an
    /// error code, `Err` when there was no usable answer at all.
    async fn call(&self, path: &str, form: &[(&str, &str)])
    -> Result<Result<Value, i64>, DsmError>;
}

pub struct HttpTransport {
    client: reqwest::Client,
    base: String,
    verifier: Option<Arc<PinningVerifier>>,
}

impl HttpTransport {
    pub fn new(conn: &Connection) -> Result<Self, DsmError> {
        // The NAS is on the LAN: a system proxy would only get in the way.
        let mut builder = reqwest::Client::builder().timeout(TIMEOUT).no_proxy();
        let verifier = if conn.https {
            let v = Arc::new(PinningVerifier::with_system_roots(
                conn.pinned_sha256.clone(),
            ));
            builder = builder.tls_backend_preconfigured(v.clone().client_config());
            Some(v)
        } else {
            None
        };
        let client = builder
            .build()
            .map_err(|e| DsmError::Transport(e.to_string()))?;
        Ok(Self {
            client,
            base: conn.base_url(),
            verifier,
        })
    }

    fn send_error(&self, e: reqwest::Error) -> DsmError {
        match self.verifier.as_ref().and_then(|v| v.take_rejection()) {
            Some(Rejection::NotTrusted(fingerprint)) => {
                DsmError::CertificateNotTrusted { fingerprint }
            }
            Some(Rejection::Changed(fingerprint)) => DsmError::CertificateChanged { fingerprint },
            None => DsmError::Transport(reason(e)),
        }
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn call(
        &self,
        path: &str,
        form: &[(&str, &str)],
    ) -> Result<Result<Value, i64>, DsmError> {
        let url = format!("{}/webapi/{path}", self.base);
        let response = self
            .client
            .post(&url)
            .form(form)
            .send()
            .await
            .map_err(|e| self.send_error(e))?;
        let response = response
            .error_for_status()
            .map_err(|e| DsmError::Transport(reason(e)))?;
        let text = response
            .text()
            .await
            .map_err(|e| DsmError::Transport(format!("unreadable response: {}", reason(e))))?;
        let body: Value = serde_json::from_str(&text)
            .map_err(|e| DsmError::Transport(format!("unreadable response: {e}")))?;
        unwrap_envelope(body)
    }
}

/// Why a request failed, e.g. "error sending request: client error
/// (Connect): tcp connect error: Connection refused (os error 111)" -
/// reqwest's own message says only the first part. The URL is dropped
/// (URLs carry no secrets anyway; form bodies never appear in errors).
fn reason(e: reqwest::Error) -> String {
    let e = e.without_url();
    let mut msg = e.to_string();
    let mut source = std::error::Error::source(&e);
    while let Some(s) = source {
        let part = s.to_string();
        if !msg.contains(&part) {
            msg.push_str(": ");
            msg.push_str(&part);
        }
        source = s.source();
    }
    msg
}

pub fn unwrap_envelope(body: Value) -> Result<Result<Value, i64>, DsmError> {
    match body["success"].as_bool() {
        Some(true) => Ok(Ok(body.get("data").cloned().unwrap_or(Value::Null))),
        Some(false) => Ok(Err(body["error"]["code"].as_i64().unwrap_or(-1))),
        None => Err(DsmError::Transport(
            "the response is not a DSM API reply".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsm::tls::fingerprint;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;

    const OK_BODY: &str = r#"{"success":true,"data":{"ok":1}}"#;

    fn response() -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{OK_BODY}",
            OK_BODY.len()
        )
    }

    fn conn(port: u16, https: bool, pinned: Option<String>) -> Connection {
        Connection {
            host: "127.0.0.1".into(),
            port,
            https,
            account: "jf".into(),
            pinned_sha256: pinned,
        }
    }

    /// Plain-HTTP server answering one request; hands back the raw request.
    async fn http_server() -> (u16, oneshot::Receiver<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 16 * 1024];
            let n = tcp.read(&mut buf).await.unwrap();
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
            tcp.write_all(response().as_bytes()).await.unwrap();
        });
        (port, rx)
    }

    /// HTTPS server with a fresh self-signed certificate; returns its port
    /// and the certificate's fingerprint.
    async fn tls_server() -> (u16, String) {
        let ck = rcgen::generate_simple_self_signed(vec!["nas.lan".to_string()]).unwrap();
        let fp = fingerprint(ck.cert.der().as_ref());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![ck.cert.der().clone()], key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(tcp).await {
                        let mut buf = vec![0u8; 16 * 1024];
                        let _ = tls.read(&mut buf).await;
                        let _ = tls.write_all(response().as_bytes()).await;
                        let _ = tls.shutdown().await;
                    }
                });
            }
        });
        (port, fp)
    }

    #[test]
    fn unwraps_dsm_envelopes() {
        assert_eq!(
            unwrap_envelope(json!({ "success": true, "data": { "a": 1 } })),
            Ok(Ok(json!({ "a": 1 })))
        );
        assert_eq!(
            unwrap_envelope(json!({ "success": true })),
            Ok(Ok(Value::Null))
        );
        assert_eq!(
            unwrap_envelope(json!({ "success": false, "error": { "code": 119 } })),
            Ok(Err(119))
        );
        assert!(matches!(
            unwrap_envelope(json!("<html>")),
            Err(DsmError::Transport(_))
        ));
    }

    #[tokio::test]
    async fn posts_a_form_body_and_keeps_secrets_out_of_the_url() {
        let (port, request) = http_server().await;
        let t = HttpTransport::new(&conn(port, false, None)).unwrap();
        let out = t
            .call(
                "entry.cgi",
                &[("api", "SYNO.API.Auth"), ("passwd", "p&ss=w+rd%ü")],
            )
            .await
            .unwrap();
        assert_eq!(out, Ok(json!({ "ok": 1 })));
        let raw = request.await.unwrap();
        let (head, body) = raw.split_once("\r\n\r\n").unwrap();
        assert!(
            head.starts_with("POST /webapi/entry.cgi HTTP/1.1"),
            "{head}"
        );
        assert!(
            !head.contains("passwd"),
            "no secrets in the request line or headers"
        );
        assert_eq!(body, "api=SYNO.API.Auth&passwd=p%26ss%3Dw%2Brd%25%C3%BC");
    }

    #[tokio::test]
    async fn unreachable_host_is_a_transport_error() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let t = HttpTransport::new(&conn(port, false, None)).unwrap();
        let err = t.call("query.cgi", &[]).await.unwrap_err();
        assert!(matches!(err, DsmError::Transport(_)), "{err:?}");
    }

    #[tokio::test]
    async fn a_refused_connection_says_why_without_the_url() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let t = HttpTransport::new(&conn(port, false, None)).unwrap();
        let DsmError::Transport(msg) = t
            .call("query.cgi", &[("passwd", "p&ss")])
            .await
            .unwrap_err()
        else {
            panic!("not a transport error");
        };
        assert!(msg.to_lowercase().contains("refused"), "{msg}");
        assert!(
            !msg.contains("webapi") && !msg.contains(&port.to_string()) && !msg.contains("p&ss"),
            "{msg}"
        );
    }

    #[tokio::test]
    async fn untrusted_certificate_reports_its_fingerprint() {
        let (port, fp) = tls_server().await;
        let t = HttpTransport::new(&conn(port, true, None)).unwrap();
        let err = t.call("query.cgi", &[]).await.unwrap_err();
        assert_eq!(err, DsmError::CertificateNotTrusted { fingerprint: fp });
    }

    #[tokio::test]
    async fn pinned_certificate_connects() {
        let (port, fp) = tls_server().await;
        let t = HttpTransport::new(&conn(port, true, Some(fp))).unwrap();
        assert_eq!(
            t.call("query.cgi", &[]).await.unwrap(),
            Ok(json!({ "ok": 1 }))
        );
    }

    #[tokio::test]
    async fn a_new_certificate_behind_a_pin_is_reported_as_changed() {
        let (port, fp) = tls_server().await;
        let t = HttpTransport::new(&conn(port, true, Some("00".repeat(32)))).unwrap();
        let err = t.call("query.cgi", &[]).await.unwrap_err();
        assert_eq!(err, DsmError::CertificateChanged { fingerprint: fp });
    }
}
