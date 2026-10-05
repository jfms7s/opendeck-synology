//! The connection's state as the user should see it - in the settings
//! panel's status line, and on keys when nothing can be shown.

use crate::dsm::error::{AuthError, DsmError};

#[derive(Debug, Clone, PartialEq, Default)]
pub enum ConnStatus {
    NotConfigured,
    #[default]
    Connecting,
    Connected {
        account: String,
    },
    Auth(AuthError),
    Certificate {
        fingerprint: String,
        changed: bool,
    },
    Unreachable(String),
    /// The keyring holds the password (or might) but can't be read now.
    Keyring(String),
    /// A keyring call is waiting on the user: macOS's Keychain access
    /// prompt (shown after each update) or a Secret Service unlock prompt.
    KeyringPending,
}

impl ConnStatus {
    /// The status an error implies, or `None` when the error is about one
    /// endpoint (permission, API error) rather than the connection.
    pub fn from_error(e: &DsmError) -> Option<Self> {
        Some(match e {
            DsmError::NotConfigured => Self::NotConfigured,
            DsmError::Transport(msg) => Self::Unreachable(msg.clone()),
            DsmError::Auth(a) => Self::Auth(*a),
            DsmError::CertificateNotTrusted { fingerprint } => Self::Certificate {
                fingerprint: fingerprint.clone(),
                changed: false,
            },
            DsmError::CertificateChanged { fingerprint } => Self::Certificate {
                fingerprint: fingerprint.clone(),
                changed: true,
            },
            DsmError::Permission { .. } | DsmError::Api { .. } | DsmError::Parse { .. } => {
                return None;
            }
        })
    }

    pub fn describe(&self) -> String {
        match self {
            Self::NotConfigured => "Not configured".into(),
            Self::Connecting => "Connecting…".into(),
            Self::Connected { account } => format!("Connected as {account}"),
            Self::Auth(AuthError::NeedOtp) => "Needs 2FA code".into(),
            Self::Auth(AuthError::BadCredentials) => "Wrong account or password".into(),
            Self::Auth(AuthError::BadOtp) => "Wrong 2FA code - try again".into(),
            Self::Auth(AuthError::Blocked) => {
                "IP blocked by DSM - unblock it in Control Panel › Security › Protection".into()
            }
            Self::Auth(other) => format!("Sign-in failed: {other}"),
            Self::Certificate { changed: false, .. } => "Certificate not trusted".into(),
            Self::Certificate { changed: true, .. } => "Certificate changed".into(),
            Self::Unreachable(msg) => format!("Unreachable: {msg}"),
            Self::Keyring(msg) => format!("Can't read the password from the system keyring: {msg}"),
            Self::KeyringPending => {
                "Waiting for the system keyring - allow access in the system prompt".into()
            }
        }
    }

    /// Machine-readable tag the settings panel switches on.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NotConfigured => "notConfigured",
            Self::Connecting => "connecting",
            Self::Connected { .. } => "connected",
            Self::Auth(AuthError::NeedOtp | AuthError::BadOtp) => "needOtp",
            Self::Auth(_) => "auth",
            Self::Certificate { .. } => "certificate",
            Self::Unreachable(_) => "unreachable",
            Self::Keyring(_) => "keyring",
            Self::KeyringPending => "keyringPending",
        }
    }

    /// How the settings panel colours the status line: "ok", "bad" or
    /// "neutral" - decided here, next to the states, not in the panel.
    pub fn severity(&self) -> &'static str {
        match self {
            Self::Connected { .. } => "ok",
            Self::NotConfigured
            | Self::Connecting
            | Self::KeyringPending
            | Self::Auth(AuthError::NeedOtp) => "neutral",
            Self::Auth(_) | Self::Certificate { .. } | Self::Unreachable(_) | Self::Keyring(_) => {
                "bad"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_connection_level_errors() {
        assert_eq!(
            ConnStatus::from_error(&DsmError::Auth(AuthError::NeedOtp)),
            Some(ConnStatus::Auth(AuthError::NeedOtp))
        );
        assert_eq!(
            ConnStatus::from_error(&DsmError::CertificateChanged {
                fingerprint: "ab".into()
            }),
            Some(ConnStatus::Certificate {
                fingerprint: "ab".into(),
                changed: true
            })
        );
        assert_eq!(
            ConnStatus::from_error(&DsmError::Transport("timed out".into())),
            Some(ConnStatus::Unreachable("timed out".into()))
        );
    }

    #[test]
    fn endpoint_level_errors_leave_the_connection_alone() {
        assert_eq!(
            ConnStatus::from_error(&DsmError::Permission { api: "x".into() }),
            None
        );
        assert_eq!(
            ConnStatus::from_error(&DsmError::Api {
                api: "x".into(),
                code: 117
            }),
            None
        );
    }

    #[test]
    fn describes_states_for_the_settings_panel() {
        assert_eq!(
            ConnStatus::Connected {
                account: "jf".into()
            }
            .describe(),
            "Connected as jf"
        );
        assert_eq!(
            ConnStatus::Auth(AuthError::NeedOtp).describe(),
            "Needs 2FA code"
        );
        assert_eq!(ConnStatus::Auth(AuthError::NeedOtp).kind(), "needOtp");
        assert!(
            ConnStatus::Auth(AuthError::Blocked)
                .describe()
                .contains("blocked")
        );
        assert_eq!(ConnStatus::Keyring("locked".into()).kind(), "keyring");
        assert_eq!(ConnStatus::KeyringPending.kind(), "keyringPending");
        assert!(
            ConnStatus::KeyringPending.describe().contains("allow"),
            "{}",
            ConnStatus::KeyringPending.describe()
        );
    }

    #[test]
    fn severity_tells_the_panel_how_to_colour_the_status() {
        let connected = ConnStatus::Connected {
            account: "jf".into(),
        };
        assert_eq!(connected.severity(), "ok");
        assert_eq!(ConnStatus::Auth(AuthError::NeedOtp).severity(), "neutral");
        assert_eq!(ConnStatus::Auth(AuthError::BadOtp).severity(), "bad");
        assert_eq!(ConnStatus::Keyring("x".into()).severity(), "bad");
        assert_eq!(ConnStatus::Connecting.severity(), "neutral");
        // Waiting on the user, not failed.
        assert_eq!(ConnStatus::KeyringPending.severity(), "neutral");
    }
}
