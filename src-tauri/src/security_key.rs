//! Hardware security keys (FIDO2) for VPN MFA and for MFA configuration.
//!
//! - **Linux and macOS:** CTAP2 over USB HID ([`hid`]). The app collects the PIN, so every
//!   ceremony verifies the user (PIN) and their presence (touch).
//! - **Windows:** not implemented yet. Windows only lets elevated processes talk to a key over
//!   HID; normal apps must use the platform WebAuthn API, which this client does not drive yet.
//!   Every ceremony fails with [`Fido2Error::Unsupported`].
//!
//! The client data the key signs is the canonical JSON of [`protocol::client_data_json`], which
//! XGuard Core rebuilds from the challenge it issued and its own origin. The relying party is
//! always the instance's own domain, never one named by Edge.
//!
//! The command glue in `commands.rs` talks to this module only.

#[cfg(not(windows))]
mod hid;
pub mod protocol;

use std::{
    sync::{Arc, LazyLock},
    time::Duration,
};

use reqwest::Url;
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

#[cfg_attr(windows, allow(unused_imports))]
use protocol::{
    ClientDataType, RelyingParty, client_data_json, decode_credential_ids, parse_creation_options,
    registration_response, validate_challenge,
};

/// How long a ceremony may wait for the user to touch the key.
pub const CEREMONY_TIMEOUT: Duration = Duration::from_secs(60);

/// One ceremony at a time: a key answers one request, and an abandoned ceremony keeps the key
/// until the key itself gives up.
static CEREMONY: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(1)));

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
    #[error("security keys are not supported by the XGuard client on this platform yet")]
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
    #[error("security key error: {0}")]
    Device(String),
}

/// Runs a blocking ceremony with the single-ceremony lock, the timeout and cancellation.
#[cfg_attr(windows, allow(dead_code))]
async fn run_ceremony<T, F>(cancel: CancellationToken, ceremony: F) -> Result<T, Fido2Error>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, Fido2Error> + Send + 'static,
{
    let deadline = tokio::time::sleep(CEREMONY_TIMEOUT);
    tokio::pin!(deadline);
    let permit = tokio::select! {
        () = cancel.cancelled() => return Err(Fido2Error::Cancelled),
        () = &mut deadline => return Err(Fido2Error::Timeout),
        permit = CEREMONY.clone().acquire_owned() => {
            permit.map_err(|_| Fido2Error::Device("ceremony lock closed".to_owned()))?
        }
    };
    // The permit travels with the blocking call, so it is released only when the key is done,
    // even if this future is dropped by a cancel.
    let task = tokio::task::spawn_blocking(move || {
        let result = ceremony();
        drop(permit);
        result
    });
    tokio::select! {
        () = cancel.cancelled() => Err(Fido2Error::Cancelled),
        () = &mut deadline => Err(Fido2Error::Timeout),
        result = task => result.map_err(|err| Fido2Error::Device(err.to_string()))?,
    }
}

#[cfg(not(windows))]
fn required_pin(pin: Option<SecretString>) -> Result<SecretString, Fido2Error> {
    match pin {
        Some(pin) if !pin.expose_secret().is_empty() => Ok(pin),
        _ => Err(Fido2Error::PinRequired),
    }
}

/// Signs `challenge` with one of `credential_ids` for the instance at `instance_url`.
pub async fn assert_for_mfa(
    instance_url: &Url,
    challenge: &str,
    credential_ids: &[String],
    pin: Option<SecretString>,
    _context: PlatformContext,
    cancel: CancellationToken,
) -> Result<Assertion, Fido2Error> {
    let rp = RelyingParty::for_instance(instance_url)?;
    validate_challenge(challenge)?;
    let credential_ids = decode_credential_ids(credential_ids)?;
    let client_data = client_data_json(ClientDataType::Get, challenge, &rp.origin);
    #[cfg(not(windows))]
    {
        let pin = required_pin(pin)?;
        run_ceremony(cancel, move || {
            hid::get_assertion(&rp.id, &client_data, &credential_ids, pin.expose_secret())
        })
        .await
    }
    #[cfg(windows)]
    {
        let _ = (pin, cancel, client_data, credential_ids, rp);
        Err(Fido2Error::Unsupported)
    }
}

/// Creates a credential for `instance_url` from a creation `challenge` (WebAuthn creation
/// options, JSON), returning the registration response to send to XGuard.
pub async fn register_security_key(
    challenge: &str,
    instance_url: &Url,
    pin: Option<SecretString>,
    _context: PlatformContext,
    cancel: CancellationToken,
) -> Result<String, Fido2Error> {
    let rp = RelyingParty::for_instance(instance_url)?;
    let options = parse_creation_options(challenge, &rp)?;
    let client_data = client_data_json(ClientDataType::Create, &options.challenge, &rp.origin);
    #[cfg(not(windows))]
    {
        let pin = required_pin(pin)?;
        let (credential_id, auth_data) = run_ceremony(cancel, {
            let client_data = client_data.clone();
            move || hid::make_credential(&options, &client_data, pin.expose_secret())
        })
        .await?;
        Ok(registration_response(
            &credential_id,
            &auth_data,
            &client_data,
        ))
    }
    #[cfg(windows)]
    {
        let _ = (pin, cancel, client_data, options);
        Err(Fido2Error::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ceremonies_run_one_at_a_time_and_can_be_cancelled() {
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let first = tokio::spawn(run_ceremony(CancellationToken::new(), move || {
            release_rx.recv().ok();
            Ok(1)
        }));
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The second waits for the key; cancelling it does not disturb the first.
        let cancel = CancellationToken::new();
        let second = tokio::spawn(run_ceremony(cancel.clone(), || Ok(2)));
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
        assert!(matches!(second.await.unwrap(), Err(Fido2Error::Cancelled)));

        release_tx.send(()).unwrap();
        assert_eq!(first.await.unwrap().unwrap(), 1);
        assert_eq!(
            run_ceremony(CancellationToken::new(), || Ok(3))
                .await
                .unwrap(),
            3
        );
    }

    #[tokio::test]
    async fn assertion_inputs_are_checked_before_the_key() {
        let url = Url::parse("https://xguard.example.com").unwrap();
        let ids = vec!["AQID".to_string()];
        let err = assert_for_mfa(
            &url,
            "bad\"challenge-0000000",
            &ids,
            Some(SecretString::from("1234")),
            PlatformContext::default(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Fido2Error::MalformedChallenge(_)));
        let err = assert_for_mfa(
            &Url::parse("https://192.168.1.1").unwrap(),
            "q83vEjRWeJA-_q83vEjRWeJA",
            &ids,
            Some(SecretString::from("1234")),
            PlatformContext::default(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Fido2Error::MalformedChallenge(_)));
        #[cfg(not(windows))]
        assert!(matches!(
            assert_for_mfa(
                &url,
                "q83vEjRWeJA-_q83vEjRWeJA",
                &ids,
                None,
                PlatformContext::default(),
                CancellationToken::new(),
            )
            .await,
            Err(Fido2Error::PinRequired)
        ));
    }
}
