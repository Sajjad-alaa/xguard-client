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

use std::{net::IpAddr, sync::LazyLock, time::Duration};

use chrono::Utc;
use reqwest::{Client, StatusCode, Url, redirect::Policy};
use xguard_client_proto::xguard::client_types::{
    DevicePostureFacts, PostureConnectRequest, PostureConnectResponse, PostureOs,
};

use crate::{
    database::{
        DbPool,
        models::{Id, instance::Instance, location::Location, wireguard_keys::WireguardKeys},
    },
    mfa::MfaError,
    proxy::construct_platform_header,
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

/// Upper bound on a posture connect response.
const MAX_POSTURE_RESPONSE_BYTES: usize = 1024 * 1024;
const POSTURE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const POSTURE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Never follows redirects so the device polling token and posture cannot be redirected elsewhere.
static POSTURE_HTTP_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    Client::builder()
        .redirect(Policy::none())
        .connect_timeout(POSTURE_CONNECT_TIMEOUT)
        .build()
        .unwrap_or_else(|err| {
            warn!("Failed to build posture HTTP client: {err}");
            Client::new()
        })
});

fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
        Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
        None => false,
    }
}

/// Builds the posture connect endpoint for `proxy_url`, requiring HTTPS (or loopback HTTP), no
/// embedded credentials, and preserving any path prefix on `proxy_url`.
pub fn posture_connect_url(proxy_url: &Url) -> Result<Url, MfaError> {
    let invalid = |reason: &str| MfaError::Other {
        message: format!("Refusing to send device posture to {proxy_url}: {reason}"),
    };
    let secure = proxy_url.scheme() == "https"
        || (proxy_url.scheme() == "http" && is_loopback_host(proxy_url));
    if !secure {
        return Err(invalid("URL must use HTTPS"));
    }
    if !proxy_url.username().is_empty() || proxy_url.password().is_some() {
        return Err(invalid("URL must not contain credentials"));
    }
    let mut base = proxy_url.clone();
    base.set_query(None);
    base.set_fragment(None);
    if !base.path().ends_with('/') {
        let path = format!("{}/", base.path());
        base.set_path(&path);
    }
    base.join("api/v1/posture/connect")
        .map_err(|err| MfaError::Other {
            message: format!("Failed to build the posture URL: {err}"),
        })
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
    let url = posture_connect_url(proxy_url)?;
    let request = PostureConnectRequest {
        location_id,
        pubkey,
        token,
        posture: Some(posture),
    };
    let mut response = POSTURE_HTTP_CLIENT
        .post(url)
        .header(CLIENT_VERSION_HEADER, PKG_VERSION)
        .header(CLIENT_PLATFORM_HEADER, construct_platform_header())
        .timeout(POSTURE_REQUEST_TIMEOUT)
        .json(&request)
        .send()
        .await
        .map_err(|err| MfaError::NetworkError {
            message: format!("Failed to reach proxy: {}", err.without_url()),
        })?;
    let status = response.status();
    if status.is_redirection() {
        return Err(MfaError::ProxyError {
            status: status.as_u16(),
            message: format!("Refused redirect ({status})"),
        });
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_POSTURE_RESPONSE_BYTES as u64)
    {
        return Err(MfaError::Other {
            message: "Posture response exceeded size limit".into(),
        });
    }
    let mut raw = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| MfaError::NetworkError {
            message: format!("Failed to read proxy response: {}", err.without_url()),
        })?
    {
        if raw.len() + chunk.len() > MAX_POSTURE_RESPONSE_BYTES {
            return Err(MfaError::Other {
                message: "Posture response exceeded size limit".into(),
            });
        }
        raw.extend_from_slice(&chunk);
    }
    if status.is_success() {
        let body: PostureConnectResponse =
            serde_json::from_slice(&raw).map_err(|err| MfaError::Other {
                message: format!("Invalid posture response: {err}"),
            })?;
        return Ok(body.preshared_key);
    }
    let body: serde_json::Value = serde_json::from_slice(&raw).unwrap_or_default();
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
        Mock, MockServer, ResponseTemplate,
        matchers::{body_partial_json, method, path},
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

    #[test]
    fn posture_connect_url_requires_tls_or_loopback_and_keeps_prefix() {
        assert_eq!(
            posture_connect_url(&Url::parse("https://edge.example.com/base?a=1#b").unwrap())
                .unwrap()
                .as_str(),
            "https://edge.example.com/base/api/v1/posture/connect"
        );
        assert!(posture_connect_url(&Url::parse("http://127.0.0.1:8080/edge").unwrap()).is_ok());
        assert!(posture_connect_url(&Url::parse("http://edge.example.com").unwrap()).is_err());
        assert!(
            posture_connect_url(&Url::parse("https://user:pw@edge.example.com").unwrap()).is_err()
        );
    }

    #[tokio::test]
    async fn posture_connect_refuses_redirects() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/posture/connect"))
            .respond_with(
                ResponseTemplate::new(307).insert_header("location", "https://evil.example/"),
            )
            .mount(&server)
            .await;
        let url = Url::parse(&server.uri()).unwrap();
        let err = posture_connect(&url, 4, "pk".into(), "tok".into(), facts())
            .await
            .unwrap_err();
        assert!(
            matches!(err, MfaError::ProxyError { status: 307, .. }),
            "{err:?}"
        );
    }
}
