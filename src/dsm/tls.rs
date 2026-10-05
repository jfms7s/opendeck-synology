//! Certificate trust for a NAS that usually has a self-signed certificate:
//! accept what the system roots accept, or exactly the certificate the user
//! pinned - never "any certificate".

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, DigitallySignedStruct, Error, OtherError, RootCertStore, SignatureScheme,
};
use sha2::{Digest, Sha256};
use std::fmt::{self, Write as _};
use std::sync::Arc;

pub fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Why a handshake was refused, carrying the offending certificate's
/// fingerprint so the settings panel can offer to trust it. It travels
/// inside the handshake's own error (see `Rejection::find`), so concurrent
/// handshakes can't mix up or lose each other's verdicts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    NotTrusted(String),
    Changed(String),
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotTrusted(_) => f.write_str("certificate not trusted"),
            Self::Changed(_) => f.write_str("certificate differs from the trusted one"),
        }
    }
}

impl std::error::Error for Rejection {}

impl Rejection {
    /// The rejection somewhere in an error's chain - however reqwest,
    /// hyper and `std::io::Error` have wrapped the rustls error.
    pub fn find(e: &(dyn std::error::Error + 'static)) -> Option<Rejection> {
        let mut cur = Some(e);
        while let Some(e) = cur {
            if let Some(r) = Self::from_rustls(e) {
                return Some(r);
            }
            // `io::Error::source` skips the error it wraps (hyper and
            // tokio-rustls nest them two deep): look inside instead.
            cur = match e.downcast_ref::<std::io::Error>() {
                Some(io) => match io.get_ref() {
                    Some(inner) => Some(inner as &(dyn std::error::Error + 'static)),
                    None => e.source(),
                },
                None => e.source(),
            };
        }
        None
    }

    fn from_rustls(e: &(dyn std::error::Error + 'static)) -> Option<Rejection> {
        match e.downcast_ref::<Error>()? {
            Error::InvalidCertificate(CertificateError::Other(OtherError(inner))) => {
                inner.downcast_ref::<Rejection>().cloned()
            }
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct PinningVerifier {
    roots: Option<Arc<WebPkiServerVerifier>>,
    pinned: Option<String>,
    provider: Arc<CryptoProvider>,
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
        Err(Error::InvalidCertificate(CertificateError::Other(
            OtherError(Arc::new(rejection)),
        )))
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
        with_roots(pinned, RootCertStore::empty())
    }

    fn with_roots(pinned: Option<String>, roots: RootCertStore) -> PinningVerifier {
        PinningVerifier::new(
            pinned,
            roots,
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
    }

    fn verify_as(
        v: &PinningVerifier,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &str,
    ) -> Result<ServerCertVerified, Error> {
        v.verify_server_cert(
            cert,
            intermediates,
            &ServerName::try_from(name.to_string()).unwrap(),
            &[],
            UnixTime::now(),
        )
    }

    fn verify(v: &PinningVerifier, cert: &CertificateDer<'_>) -> Result<ServerCertVerified, Error> {
        verify_as(v, cert, &[], "nas.lan")
    }

    fn rejection(r: Result<ServerCertVerified, Error>) -> Option<Rejection> {
        Rejection::find(&r.err()?)
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
        assert_eq!(
            rejection(verify(&v, &cert)),
            Some(Rejection::NotTrusted(fingerprint(cert.as_ref())))
        );
    }

    #[test]
    fn pinned_certificate_is_accepted_case_insensitively() {
        let cert = self_signed();
        let v = verifier(Some(fingerprint(cert.as_ref()).to_uppercase()));
        assert!(verify(&v, &cert).is_ok());
    }

    #[test]
    fn a_different_certificate_than_the_pin_is_a_change() {
        let pinned = fingerprint(self_signed().as_ref());
        let other = self_signed();
        let v = verifier(Some(pinned));
        assert_eq!(
            rejection(verify(&v, &other)),
            Some(Rejection::Changed(fingerprint(other.as_ref())))
        );
    }

    #[test]
    fn a_rejection_is_found_however_deeply_it_is_wrapped() {
        let r = Rejection::NotTrusted("ab".into());
        let tls =
            Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(r.clone()))));
        let nested =
            std::io::Error::other(std::io::Error::new(std::io::ErrorKind::InvalidData, tls));
        assert_eq!(Rejection::find(&nested), Some(r));
    }

    #[test]
    fn other_errors_carry_no_rejection() {
        let e = std::io::Error::other(Error::InvalidCertificate(CertificateError::Expired));
        assert_eq!(Rejection::find(&e), None);
    }

    /// A CA and a leaf for `nas.lan` it signed.
    fn ca_and_leaf() -> (CertificateDer<'static>, CertificateDer<'static>) {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["nas.lan".to_string()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();
        (ca.der().clone(), leaf.der().clone())
    }

    #[test]
    fn a_certificate_the_system_roots_vouch_for_is_accepted_for_its_name_only() {
        let (ca, leaf) = ca_and_leaf();
        let mut roots = RootCertStore::empty();
        roots.add(ca).unwrap();
        let v = with_roots(None, roots);
        assert!(verify_as(&v, &leaf, &[], "nas.lan").is_ok());
        assert_eq!(
            rejection(verify_as(&v, &leaf, &[], "other.lan")),
            Some(Rejection::NotTrusted(fingerprint(leaf.as_ref()))),
            "a valid certificate for another name is not trusted"
        );
    }
}
