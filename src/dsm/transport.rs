//! The wire: POST a form to `/webapi/<path>` and unwrap DSM's
//! `{success, data | error}` envelope. Every parameter goes in the POST
//! body, so the password, 2FA code and session id never appear in a URL,
//! a proxy log or an error message.

use crate::dsm::error::DsmError;
use crate::dsm::tls::{PinningVerifier, Rejection};
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

pub(crate) const TIMEOUT: Duration = Duration::from_secs(10);

/// Where to reach DSM, in the `dsm` layer's own terms (the plugin's
/// settings turn into this, so a settings change doesn't reach the wire).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// `https://nas.lan:5001`
    pub base_url: String,
    pub https: bool,
    /// SHA-256 of the trusted leaf certificate (lowercase hex).
    pub pinned_sha256: Option<String>,
}

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
}

impl HttpTransport {
    pub fn new(target: &Target) -> Result<Self, DsmError> {
        // The NAS is on the LAN: a system proxy would only get in the way.
        // DSM's API never redirects; following one would replay the login
        // form (password, 2FA code, device token) to wherever it points.
        let mut builder = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none());
        if target.https {
            let v = Arc::new(PinningVerifier::with_system_roots(
                target.pinned_sha256.clone(),
            ));
            builder = builder
                .tls_backend_preconfigured(v.client_config())
                .https_only(true);
        }
        let client = builder
            .build()
            .map_err(|e| DsmError::Transport(e.to_string()))?;
        Ok(Self {
            client,
            base: target.base_url.clone(),
        })
    }
}

/// A failed request as the plugin should treat it: the certificate verdict
/// rides inside the error itself, so each request reports its own.
fn send_error(e: reqwest::Error) -> DsmError {
    match Rejection::find(&e) {
        Some(Rejection::NotTrusted(fingerprint)) => DsmError::CertificateNotTrusted { fingerprint },
        Some(Rejection::Changed(fingerprint)) => DsmError::CertificateChanged { fingerprint },
        None => DsmError::Transport(reason(e)),
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
            .map_err(send_error)?;
        if response.status().is_redirection() {
            return Err(DsmError::Transport(format!(
                "the NAS answered with a redirect (HTTP {}); check the host, port and HTTPS setting",
                response.status().as_u16()
            )));
        }
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
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;
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

    fn target(port: u16, https: bool, pinned: Option<String>) -> Target {
        let scheme = if https { "https" } else { "http" };
        Target {
            base_url: format!("{scheme}://127.0.0.1:{port}"),
            https,
            pinned_sha256: pinned,
        }
    }

    /// Plain-HTTP server answering one request with `reply`; hands back the
    /// raw request.
    async fn http_server_replying(reply: String) -> (u16, oneshot::Receiver<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 16 * 1024];
            let n = tcp.read(&mut buf).await.unwrap();
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
            tcp.write_all(reply.as_bytes()).await.unwrap();
        });
        (port, rx)
    }

    async fn http_server() -> (u16, oneshot::Receiver<String>) {
        http_server_replying(response()).await
    }

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    }

    /// Presents `cert` but signs the handshake with `key` - which, for a
    /// forged server, is not the certificate's own key.
    #[derive(Debug)]
    struct Presents(Arc<CertifiedKey>);

    impl ResolvesServerCert for Presents {
        fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    /// HTTPS server answering every request; `versions` limits the TLS
    /// versions it speaks.
    async fn tls_server_with(
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> u16 {
        let signer = provider().key_provider.load_private_key(key).unwrap();
        let resolver = Presents(Arc::new(CertifiedKey::new(vec![cert], signer)));
        let config = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
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
        port
    }

    fn key_der(k: &rcgen::KeyPair) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(k.serialize_der()))
    }

    /// HTTPS server with a fresh self-signed certificate; returns its port
    /// and the certificate's fingerprint.
    async fn tls_server() -> (u16, String) {
        let ck = rcgen::generate_simple_self_signed(vec!["nas.lan".to_string()]).unwrap();
        let fp = fingerprint(ck.cert.der().as_ref());
        let port = tls_server_with(
            ck.cert.der().clone(),
            key_der(&ck.signing_key),
            rustls::DEFAULT_VERSIONS,
        )
        .await;
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
        let t = HttpTransport::new(&target(port, false, None)).unwrap();
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
        let t = HttpTransport::new(&target(port, false, None)).unwrap();
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
        let t = HttpTransport::new(&target(port, false, None)).unwrap();
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
        let t = HttpTransport::new(&target(port, true, None)).unwrap();
        let err = t.call("query.cgi", &[]).await.unwrap_err();
        assert_eq!(err, DsmError::CertificateNotTrusted { fingerprint: fp });
    }

    #[tokio::test]
    async fn pinned_certificate_connects() {
        let (port, fp) = tls_server().await;
        let t = HttpTransport::new(&target(port, true, Some(fp))).unwrap();
        assert_eq!(
            t.call("query.cgi", &[]).await.unwrap(),
            Ok(json!({ "ok": 1 }))
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_handshakes_each_report_the_certificate() {
        let (port, fp) = tls_server().await;
        let t = Arc::new(HttpTransport::new(&target(port, true, Some("00".repeat(32)))).unwrap());
        let calls = (0..8).map(|_| {
            let t = t.clone();
            tokio::spawn(async move { t.call("query.cgi", &[]).await })
        });
        for r in futures::future::join_all(calls).await {
            assert_eq!(
                r.unwrap().unwrap_err(),
                DsmError::CertificateChanged {
                    fingerprint: fp.clone()
                },
                "no request mistaken for a network error"
            );
        }
    }

    /// A server that replays the pinned certificate without its private key
    /// must fail the handshake signature check, in either TLS version.
    async fn forged_server_is_refused(version: &'static rustls::SupportedProtocolVersion) {
        let real = rcgen::generate_simple_self_signed(vec!["nas.lan".to_string()]).unwrap();
        let other_key = rcgen::KeyPair::generate().unwrap();
        let port = tls_server_with(real.cert.der().clone(), key_der(&other_key), &[version]).await;
        let pin = fingerprint(real.cert.der().as_ref());
        let t = HttpTransport::new(&target(port, true, Some(pin))).unwrap();
        let err = t.call("query.cgi", &[]).await.unwrap_err();
        assert!(matches!(err, DsmError::Transport(_)), "{err:?}");
    }

    #[tokio::test]
    async fn a_replayed_certificate_without_its_key_fails_tls13() {
        forged_server_is_refused(&rustls::version::TLS13).await;
    }

    #[tokio::test]
    async fn a_replayed_certificate_without_its_key_fails_tls12() {
        forged_server_is_refused(&rustls::version::TLS12).await;
    }

    #[tokio::test]
    async fn the_real_key_passes_in_both_tls_versions() {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let ck = rcgen::generate_simple_self_signed(vec!["nas.lan".to_string()]).unwrap();
            let port =
                tls_server_with(ck.cert.der().clone(), key_der(&ck.signing_key), &[version]).await;
            let pin = fingerprint(ck.cert.der().as_ref());
            let t = HttpTransport::new(&target(port, true, Some(pin))).unwrap();
            assert_eq!(t.call("q", &[]).await.unwrap(), Ok(json!({ "ok": 1 })));
        }
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let (elsewhere, followed) = http_server().await;
        let reply = format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{elsewhere}/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let (port, _) = http_server_replying(reply).await;
        let t = HttpTransport::new(&target(port, false, None)).unwrap();
        let DsmError::Transport(msg) = t
            .call("entry.cgi", &[("passwd", "secret")])
            .await
            .unwrap_err()
        else {
            panic!("not a transport error")
        };
        assert!(msg.contains("redirect"), "{msg}");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut followed = followed;
        assert!(
            followed.try_recv().is_err(),
            "the login form went nowhere else"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_nas_that_never_answers_times_out_after_ten_seconds() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (_tcp, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let t = HttpTransport::new(&target(port, false, None)).unwrap();
        let t0 = tokio::time::Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(60), t.call("query.cgi", &[]))
            .await
            .expect("the transport's own timeout fires first");
        assert!(matches!(result, Err(DsmError::Transport(_))), "{result:?}");
        assert_eq!(t0.elapsed(), TIMEOUT);
        assert_eq!(TIMEOUT, Duration::from_secs(10));
    }

    #[tokio::test]
    async fn a_new_certificate_behind_a_pin_is_reported_as_changed() {
        let (port, fp) = tls_server().await;
        let t = HttpTransport::new(&target(port, true, Some("00".repeat(32)))).unwrap();
        let err = t.call("query.cgi", &[]).await.unwrap_err();
        assert_eq!(err, DsmError::CertificateChanged { fingerprint: fp });
    }
}
