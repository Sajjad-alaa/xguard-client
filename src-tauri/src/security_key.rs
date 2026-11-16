//! Hardware security keys (FIDO2) for VPN MFA and for MFA configuration.
//!
//! XGuard does not drive security keys yet: every ceremony fails with
//! [`Fido2Error::Unsupported`], and XGuard Core never offers FIDO2 to clients, so these paths are
//! only reached against servers that do. The command glue in `commands.rs` talks to this module
//! only, so a real implementation can replace these functions without touching the commands.

use std::time::Duration;

use reqwest::Url;
use tokio_util::sync::CancellationToken;

/// How long a ceremony may wait for the user to touch the key.
#[allow(dead_code)]
pub const CEREMONY_TIMEOUT: Duration = Duration::from_secs(60);

/// Who asks the user for the key's PIN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinPolicy {
    /// The operating system collects the PIN in its own dialog (Windows WebAuthn).
    Platform,
    /// The app collects the PIN and hands it to the ceremony.
    App,
}

#[must_use]
pub fn pin_policy() -> PinPolicy {
    if cfg!(windows) {
        PinPolicy::Platform
    } else {
        PinPolicy::App
    }
}

/// The window a platform prompt should be attached to, where the platform has one.
#[derive(Clone, Copy, Debug, Default)]
pub struct PlatformContext {
    #[allow(dead_code)]
    window_handle: Option<isize>,
}

impl PlatformContext {
    #[must_use]
    pub fn new(window_handle: Option<isize>) -> Self {
        Self { window_handle }
    }
}

/// A signed WebAuthn assertion.
#[derive(Debug)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum Fido2Error {
    #[error("security keys are not supported by this XGuard client yet")]
    Unsupported,
    #[error("no security key found")]
    NoDevice,
    #[error("more than one security key found")]
    MultipleDevices,
    #[error("timed out waiting for the security key")]
    Timeout,
    #[error("the security key holds no matching credential")]
    NoCredentials,
    #[error("the operation was not allowed")]
    NotAllowed,
    #[error("the security key is already registered")]
    CredentialExcluded,
    #[error("the authenticator is not a roaming security key")]
    NotASecurityKey,
    #[error("a PIN is required")]
    PinRequired,
    #[error("the PIN is incorrect")]
    PinInvalid,
    #[error("the PIN is blocked")]
    PinBlocked,
    #[error("cancelled")]
    Cancelled,
    #[error("malformed challenge: {0}")]
    MalformedChallenge(String),
}

/// Signs `challenge` with one of `credential_ids` for relying party `rp_id`.
pub async fn assert_for_mfa(
    _rp_id: &str,
    _challenge: &str,
    _credential_ids: &[String],
    _pin: Option<String>,
    _context: PlatformContext,
    _cancel: CancellationToken,
) -> Result<Assertion, Fido2Error> {
    Err(Fido2Error::Unsupported)
}

/// Creates a credential for `instance_url` from a creation `challenge`, returning the
/// attestation to send to XGuard.
pub async fn register_security_key(
    _challenge: &str,
    _instance_url: &Url,
    _pin: Option<String>,
    _context: PlatformContext,
    _cancel: CancellationToken,
) -> Result<String, Fido2Error> {
    Err(Fido2Error::Unsupported)
}
