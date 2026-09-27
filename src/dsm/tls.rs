//! Certificate trust for a NAS that usually has a self-signed certificate:
//! accept what the system roots accept, or exactly the certificate the user
//! pinned - never "any certificate".

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

pub fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Why the last handshake was refused, carrying the offending certificate's
/// fingerprint so the settings panel can offer to trust it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    NotTrusted(String),
    Changed(String),
}

#[derive(Debug)]
pub struct PinningVerifier {
    roots: Option<Arc<WebPkiServerVerifier>>,
    pinned: Option<String>,
    provider: Arc<CryptoProvider>,
    rejected: Mutex<Option<Rejection>>,
}

impl PinningVerifier {
    pub fn new(
        pinned: Option<String>,
        roots: RootCertStore,
        provider: Arc<CryptoProvider>,
    ) -> Self {
        let roots = if roots.is_empty() {
            None
        } else {
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .ok()
        };
        Self {
            roots,
            pinned: pinned.map(|p| p.to_lowercase()),
            provider,
            rejected: Mutex::new(None),
        }
    }

    pub fn with_system_roots(pinned: Option<String>) -> Self {
        let loaded = rustls_native_certs::load_native_certs();
        for e in &loaded.errors {
            log::warn!("system certificate store: {e}");
        }
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(loaded.certs);
        Self::new(
            pinned,
            roots,
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
    }

    /// Why the last handshake was refused, if it was. Reading clears it.
    pub fn take_rejection(&self) -> Option<Rejection> {
        self.rejected.lock().unwrap().take()
    }

    pub fn client_config(self: Arc<Self>) -> rustls::ClientConfig {
        rustls::ClientConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .expect("the default provider supports the default TLS versions")
            .dangerous()
            .with_custom_certificate_verifier(self)
            .with_no_client_auth()
    }
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let fp = fingerprint(end_entity.as_ref());
        // The pin is the trust anchor, so the hostname isn't checked for it:
        // users reach their NAS by IP as often as by name.
        if self.pinned.as_deref() == Some(fp.as_str()) {
            return Ok(ServerCertVerified::assertion());
        }
        if let Some(roots) = &self.roots
            && roots
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
                .is_ok()
        {
            return Ok(ServerCertVerified::assertion());
        }
        let rejection = if self.pinned.is_some() {
            Rejection::Changed(fp)
        } else {
            Rejection::NotTrusted(fp)
        };
        *self.rejected.lock().unwrap() = Some(rejection);
        Err(Error::InvalidCertificate(CertificateError::UnknownIssuer))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn self_signed() -> CertificateDer<'static> {
        rcgen::generate_simple_self_signed(vec!["nas.lan".to_string()])
            .unwrap()
            .cert
            .der()
            .clone()
    }

    fn verifier(pinned: Option<String>) -> PinningVerifier {
        PinningVerifier::new(
            pinned,
            RootCertStore::empty(),
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
    }

    fn verify(v: &PinningVerifier, cert: &CertificateDer<'_>) -> Result<ServerCertVerified, Error> {
        v.verify_server_cert(
            cert,
            &[],
            &ServerName::try_from("nas.lan").unwrap(),
            &[],
            UnixTime::now(),
        )
    }

    #[test]
    fn fingerprint_is_lowercase_sha256_hex() {
        assert_eq!(
            fingerprint(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn unknown_certificate_is_rejected_with_its_fingerprint() {
        let cert = self_signed();
        let v = verifier(None);
        assert!(verify(&v, &cert).is_err());
        assert_eq!(
            v.take_rejection(),
            Some(Rejection::NotTrusted(fingerprint(cert.as_ref())))
        );
        assert_eq!(v.take_rejection(), None, "reading clears it");
    }

    #[test]
    fn pinned_certificate_is_accepted_case_insensitively() {
        let cert = self_signed();
        let v = verifier(Some(fingerprint(cert.as_ref()).to_uppercase()));
        assert!(verify(&v, &cert).is_ok());
        assert_eq!(v.take_rejection(), None);
    }

    #[test]
    fn a_different_certificate_than_the_pin_is_a_change() {
        let pinned = fingerprint(self_signed().as_ref());
        let other = self_signed();
        let v = verifier(Some(pinned));
        assert!(verify(&v, &other).is_err());
        assert_eq!(
            v.take_rejection(),
            Some(Rejection::Changed(fingerprint(other.as_ref())))
        );
    }
}
