//! What can go wrong talking to DSM, sorted by what the plugin should do
//! about it: retry later (transport, API), or stop and wait for the user
//! (credentials, certificate, missing settings).

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthError {
    #[error("2FA code required")]
    NeedOtp,
    #[error("wrong account or password")]
    BadCredentials,
    #[error("wrong 2FA code")]
    BadOtp,
    #[error("IP blocked by DSM")]
    Blocked,
    #[error("password expired")]
    PasswordExpired,
    #[error("2FA is enforced but not set up for this account")]
    OtpEnforced,
    #[error("account disabled or not allowed to sign in")]
    Disabled,
}

impl AuthError {
    /// Maps a `SYNO.API.Auth` login error code; `None` for codes that are not
    /// about the credentials (those surface as `DsmError::Api`).
    pub fn from_login_code(code: i64) -> Option<Self> {
        Some(match code {
            400 => Self::BadCredentials,
            401 | 402 => Self::Disabled,
            403 => Self::NeedOtp,
            404 => Self::BadOtp,
            406 => Self::OtpEnforced,
            407 => Self::Blocked,
            408..=410 => Self::PasswordExpired,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Error)]
pub enum DsmError {
    #[error("connection settings are incomplete")]
    NotConfigured,
    #[error("unreachable: {0}")]
    Transport(String),
    #[error("certificate not trusted (SHA-256 {fingerprint})")]
    CertificateNotTrusted { fingerprint: String },
    #[error("certificate changed (SHA-256 {fingerprint})")]
    CertificateChanged { fingerprint: String },
    #[error("{0}")]
    Auth(#[from] AuthError),
    #[error("no permission for {api}")]
    Permission { api: String },
    #[error("{api} failed with DSM error {code}")]
    Api { api: String, code: i64 },
    #[error("unexpected response from {api}: {detail}")]
    Parse { api: String, detail: String },
}

impl DsmError {
    /// Errors only the user can fix. Pollers stop retrying on these:
    /// retrying a wrong password is exactly what trips DSM's auto-block.
    pub fn needs_user(&self) -> bool {
        matches!(
            self,
            Self::NotConfigured
                | Self::Auth(_)
                | Self::CertificateNotTrusted { .. }
                | Self::CertificateChanged { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_login_codes() {
        assert_eq!(
            AuthError::from_login_code(400),
            Some(AuthError::BadCredentials)
        );
        assert_eq!(AuthError::from_login_code(402), Some(AuthError::Disabled));
        assert_eq!(AuthError::from_login_code(403), Some(AuthError::NeedOtp));
        assert_eq!(AuthError::from_login_code(404), Some(AuthError::BadOtp));
        assert_eq!(
            AuthError::from_login_code(406),
            Some(AuthError::OtpEnforced)
        );
        assert_eq!(AuthError::from_login_code(407), Some(AuthError::Blocked));
        assert_eq!(
            AuthError::from_login_code(409),
            Some(AuthError::PasswordExpired)
        );
        assert_eq!(AuthError::from_login_code(119), None);
    }

    #[test]
    fn only_user_fixable_errors_pause_polling() {
        assert!(DsmError::Auth(AuthError::BadCredentials).needs_user());
        assert!(DsmError::NotConfigured.needs_user());
        assert!(
            DsmError::CertificateChanged {
                fingerprint: "ab".into()
            }
            .needs_user()
        );
        assert!(!DsmError::Transport("timeout".into()).needs_user());
        assert!(!DsmError::Permission { api: "x".into() }.needs_user());
        assert!(
            !DsmError::Api {
                api: "x".into(),
                code: 117
            }
            .needs_user()
        );
    }
}
