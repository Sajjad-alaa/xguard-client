//! XGuard device posture: facts about this device, reported when connecting to a location with
//! posture policies.
//!
//! - [`collect`] gathers the facts with read-only probes (see [`collect`](self::collect)), all
//!   within [`COLLECTION_TIMEOUT`].
//! - For a location with MFA the facts go with the MFA start request; for a location without
//!   MFA, [`posture_connect`] sends them to Edge, which answers with the session's preshared
//!   key.
//!
//! The facts are an attestation by this client, not proof: the server cannot verify them.

use std::time::Duration;

use chrono::Utc;
use reqwest::{StatusCode, Url};
use xguard_client_proto::xguard::client_types::{
    DevicePostureFacts, PostureConnectRequest, PostureConnectResponse, PostureOs,
};

use crate::{
    database::{
        models::{instance::Instance, location::Location, wireguard_keys::WireguardKeys, Id},
        DbPool,
    },
    mfa::MfaError,
    proxy::{construct_platform_header, http_client},
    version::{CLIENT_PLATFORM_HEADER, CLIENT_VERSION_HEADER, PKG_VERSION},
};

mod collect;
pub mod parse;

/// Upper bound for collecting all facts.
pub const COLLECTION_TIMEOUT: Duration = Duration::from_secs(20);
/// Edge error code of a posture refusal.
pub const POSTURE_REJECTED_CODE: &str = "posture_rejected";
/// Message prefix of a posture refusal from XGuard core.
pub const POSTURE_REJECTED_PREFIX: &str = "Device posture check failed";

fn this_os() -> PostureOs {
    match std::env::consts::OS {
        "linux" => PostureOs::Linux,
        "macos" => PostureOs::Macos,
        "windows" => PostureOs::Windows,
        _ => PostureOs::Unspecified,
    }
}

/// The OS version (`14.5`, `10.0.22631`, `24.04`) and a display name, from `os_info`.
fn os_version_and_name() -> (Option<String>, Option<String>) {
    let info = os_info::get();
    let version = match info.version() {
        os_info::Version::Unknown => None,
        version => Some(version.to_string()),
    };
    let name = Some(
        format!("{} {}", info.os_type(), info.version())
            .trim()
            .to_string(),
    );
    (version, name)
}

/// Collects posture facts about this device. Never fails: unknown facts stay unset.
pub async fn collect() -> DevicePostureFacts {
    let platform = tokio::time::timeout(COLLECTION_TIMEOUT, collect::platform_facts())
        .await
        .unwrap_or_else(|_| {
            warn!("Collecting device posture timed out");
            collect::PlatformFacts::default()
        });
    let (os_version, os_name) = tokio::task::spawn_blocking(os_version_and_name)
        .await
        .unwrap_or_default();
    let facts = DevicePostureFacts {
        os: this_os() as i32,
        os_version,
        os_name,
        kernel_version: platform.kernel_version,
        client_version: PKG_VERSION.to_string(),
        disk_encrypted: platform.disk_encrypted,
        firewall_enabled: platform.firewall_enabled,
        screen_lock_enabled: platform.screen_lock_enabled,
        antivirus_enabled: platform.antivirus_enabled,
        domain_joined: platform.domain_joined,
        device_integrity: platform.device_integrity,
        security_update_age_days: platform.security_update_age_days,
        security_patch_date: None,
        collected_at: Utc::now().timestamp(),
    };
    debug!("Collected device posture: {facts:?}");
    facts
}

/// Whether an Edge error response is a posture refusal.
#[must_use]
pub fn is_posture_rejection(status: StatusCode, code: Option<&str>, message: &str) -> bool {
    status == StatusCode::FORBIDDEN
        && (code == Some(POSTURE_REJECTED_CODE) || message.starts_with(POSTURE_REJECTED_PREFIX))
}

/// The failed checks of a refusal, comma-separated as the connect views list them.
#[must_use]
pub fn rejection_reasons(message: &str) -> String {
    message
        .strip_prefix(POSTURE_REJECTED_PREFIX)
        .map_or(message, |rest| rest.trim_start_matches(':').trim())
        .split("; ")
        .collect::<Vec<_>>()
        .join(", ")
}

/// Connects to a location that has posture policies but no MFA: sends the facts to Edge and
/// returns the session's preshared key (empty when the location no longer needs one).
pub async fn posture_connect(
    proxy_url: &Url,
    location_id: i64,
    pubkey: String,
    token: String,
    posture: DevicePostureFacts,
) -> Result<String, MfaError> {
    let url = proxy_url
        .join("api/v1/posture/connect")
        .map_err(|err| MfaError::Other {
            message: format!("Failed to build the posture URL: {err}"),
        })?;
    let request = PostureConnectRequest {
        location_id,
        pubkey,
        token,
        posture: Some(posture),
    };
    let response = http_client()
        .post(url)
        .header(CLIENT_VERSION_HEADER, PKG_VERSION)
        .header(CLIENT_PLATFORM_HEADER, construct_platform_header())
        .timeout(Duration::from_secs(30))
        .json(&request)
        .send()
        .await
        .map_err(|err| MfaError::NetworkError {
            message: format!("Failed to reach proxy: {err}"),
        })?;
    let status = response.status();
    if status.is_success() {
        let body: PostureConnectResponse =
            response.json().await.map_err(|err| MfaError::Other {
                message: format!("Invalid posture response: {err}"),
            })?;
        return Ok(body.preshared_key);
    }
    let body: serde_json::Value = response.json().await.unwrap_or_default();
    let message = body
        .get("error")
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| format!("HTTP {status}"), str::to_string);
    let code = body.get("code").and_then(serde_json::Value::as_str);
    if is_posture_rejection(status, code, &message) {
        return Err(MfaError::PostureRejected {
            message: rejection_reasons(&message),
        });
    }
    if status.is_client_error() {
        Err(MfaError::MfaRejected { message })
    } else {
        Err(MfaError::ProxyError {
            status: status.as_u16(),
            message,
        })
    }
}

/// Authorizes a posture-only location (posture policies, no MFA) and returns the preshared key to
/// connect with, `None` when the location no longer needs one.
pub async fn authorize_location(
    pool: &DbPool,
    location: &Location<Id>,
) -> Result<Option<String>, MfaError> {
    let other = |message: String| MfaError::Other { message };
    let instance = Instance::find_by_id(pool, location.instance_id)
        .await
        .map_err(|err| other(format!("Failed to load the instance: {err}")))?
        .ok_or_else(|| other("Instance not found".into()))?;
    let token = instance
        .token
        .clone()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            other(format!(
                "Instance {} has no device token; enroll this device again to connect to {}",
                instance.name, location.name
            ))
        })?;
    let keys = WireguardKeys::find_by_instance_id(pool, instance.id)
        .await
        .map_err(|err| other(format!("Failed to load WireGuard keys: {err}")))?
        .ok_or_else(|| other(format!("WireGuard keys not found for {}", instance.name)))?;
    let proxy_url = Url::parse(&instance.proxy_url)
        .map_err(|err| other(format!("Invalid proxy URL: {err}")))?;
    info!("Checking device posture for location {}", location.name);
    let facts = collect().await;
    let key = posture_connect(&proxy_url, location.network_id, keys.pubkey, token, facts).await?;
    Ok(Some(key).filter(|key| !key.is_empty()))
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        matchers::{body_partial_json, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::*;

    #[tokio::test]
    async fn collect_reports_the_basics_quickly() {
        let started = std::time::Instant::now();
        let facts = collect().await;
        assert!(started.elapsed() < COLLECTION_TIMEOUT + Duration::from_secs(5));
        assert_eq!(facts.client_version, PKG_VERSION);
        assert_ne!(facts.os, PostureOs::Unspecified as i32);
        assert!(facts.collected_at > 0);
        #[cfg(target_os = "linux")]
        assert!(facts.kernel_version.is_some());
    }

    fn facts() -> DevicePostureFacts {
        DevicePostureFacts {
            os: PostureOs::Linux as i32,
            client_version: "2.2.0".into(),
            disk_encrypted: Some(true),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn posture_connect_returns_key() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/posture/connect"))
            .and(body_partial_json(json!({
                "location_id": 4,
                "pubkey": "pk",
                "token": "tok",
                "posture": {"disk_encrypted": true, "client_version": "2.2.0"},
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"preshared_key": "psk"})))
            .expect(1)
            .mount(&server)
            .await;
        let url = Url::parse(&server.uri()).unwrap();
        let key = posture_connect(&url, 4, "pk".into(), "tok".into(), facts())
            .await
            .unwrap();
        assert_eq!(key, "psk");
    }

    #[tokio::test]
    async fn posture_connect_reports_rejection() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/posture/connect"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "error": "Device posture check failed: disk encryption is required",
                "code": "posture_rejected",
            })))
            .mount(&server)
            .await;
        let url = Url::parse(&server.uri()).unwrap();
        let err = posture_connect(&url, 4, "pk".into(), "tok".into(), facts())
            .await
            .unwrap_err();
        match err {
            MfaError::PostureRejected { message } => {
                assert!(message.contains("disk encryption is required"));
            }
            other => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn rejection_reasons_are_listed() {
        assert_eq!(
            rejection_reasons(
                "Device posture check failed: disk encryption is required; firewall is required"
            ),
            "disk encryption is required, firewall is required"
        );
        assert_eq!(rejection_reasons("something else"), "something else");
    }

    #[test]
    fn rejection_detection() {
        assert!(is_posture_rejection(
            StatusCode::FORBIDDEN,
            Some("posture_rejected"),
            "x"
        ));
        assert!(is_posture_rejection(
            StatusCode::FORBIDDEN,
            None,
            "Device posture check failed: firewall is required"
        ));
        assert!(!is_posture_rejection(
            StatusCode::FORBIDDEN,
            None,
            "Too many failed MFA attempts."
        ));
        assert!(!is_posture_rejection(
            StatusCode::UNAUTHORIZED,
            Some("posture_rejected"),
            "x"
        ));
    }
}
