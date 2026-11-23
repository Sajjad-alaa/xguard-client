use std::{env, net::IpAddr, sync::LazyLock, time::Duration};

use base64::{Engine, prelude::BASE64_STANDARD};
use prost::Message;
use reqwest::{Client, Response, Url, redirect::Policy};
use serde::Serialize;
use xguard_client_proto::xguard::client_types::ClientPlatformInfo;

use crate::version::{CLIENT_PLATFORM_HEADER, CLIENT_VERSION_HEADER, PKG_VERSION};

const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_REQ_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_CLIENT_TIMEOUT: Duration = Duration::from_secs(30);

/// Shared across every proxy request, so the connection pool and TLS session cache survive
/// between them. Redirects are disabled so tokens/cookies are never forwarded to another host.
static HTTP_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    Client::builder()
        .redirect(Policy::none())
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .timeout(HTTP_CLIENT_TIMEOUT)
        .build()
        .unwrap_or_else(|err| {
            error!("Failed to build shared proxy HTTP client: {err}");
            Client::new()
        })
});

#[must_use]
pub fn is_loopback_proxy_url(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
        Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
        None => false,
    }
}

/// Validates that a proxy base URL uses HTTPS (or loopback HTTP), specifies a host, and
/// carries no embedded username or password.
pub fn validate_proxy_url(url: &Url) -> Result<(), &'static str> {
    if url.host_str().is_none() {
        return Err("Proxy URL missing host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Proxy URL must not contain credentials");
    }
    if url.scheme() == "https" || (url.scheme() == "http" && is_loopback_proxy_url(url)) {
        Ok(())
    } else {
        Err("Proxy URL must use HTTPS (or http:// to localhost)")
    }
}

/// Validates `base` as a proxy URL, strips any query/fragment, ensures a trailing slash on the
/// path so a proxy path prefix is preserved, and joins `endpoint`.
pub fn join_proxy_endpoint(base: &Url, endpoint: &str) -> Result<Url, String> {
    validate_proxy_url(base).map_err(|reason| format!("{reason}: {base}"))?;
    let mut normalized = base.clone();
    normalized.set_query(None);
    normalized.set_fragment(None);
    if !normalized.path().ends_with('/') {
        let with_slash = format!("{}/", normalized.path());
        normalized.set_path(&with_slash);
    }
    normalized
        .join(endpoint.trim_start_matches('/'))
        .map_err(|err| format!("Failed to build endpoint URL '{endpoint}': {err}"))
}

/// The platform does not change while the process runs, and `os_info::get` is a registry probe
/// on Windows and a file read elsewhere - not something to repeat per request.
static PLATFORM_HEADER: LazyLock<String> = LazyLock::new(build_platform_header);

#[must_use]
pub fn http_client() -> &'static Client {
    &HTTP_CLIENT
}

/// A base64-encoded `ClientPlatformInfo` header value, built once.
#[must_use]
pub fn construct_platform_header() -> String {
    PLATFORM_HEADER.clone()
}

fn build_platform_header() -> String {
    let os = os_info::get();

    let platform_info = ClientPlatformInfo {
        os_family: env::consts::FAMILY.to_string(),
        os_type: env::consts::OS.to_string(),
        version: os.version().to_string(),
        edition: os.edition().map(str::to_string),
        codename: os.codename().map(str::to_string),
        bitness: Some(os.bitness().to_string()),
        architecture: Some(env::consts::ARCH.to_string()),
    };

    debug!("Constructed platform info header: {platform_info:?}");

    BASE64_STANDARD.encode(platform_info.encode_to_vec())
}

/// Send a JSON POST request with the standard client version/platform headers and a short timeout.
pub async fn post_with_headers<T: Serialize + ?Sized>(
    url: Url,
    data: &T,
) -> Result<Response, reqwest::Error> {
    http_client()
        .post(url)
        .json(data)
        .header(CLIENT_VERSION_HEADER, PKG_VERSION)
        .header(CLIENT_PLATFORM_HEADER, construct_platform_header())
        .timeout(HTTP_REQ_TIMEOUT)
        .send()
        .await
}

/// Falls back to the status line when the body is absent, empty or not the expected shape.
pub async fn read_error_message(response: Response) -> String {
    let status = response.status();
    response
        .json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|body| {
            body.get("error")
                .and_then(serde_json::Value::as_str)
                .map(String::from)
        })
        .unwrap_or_else(|| format!("HTTP {status}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_proxy_url() {
        assert!(validate_proxy_url(&Url::parse("https://proxy.example.com").unwrap()).is_ok());
        assert!(validate_proxy_url(&Url::parse("http://127.0.0.1:8080/base").unwrap()).is_ok());
        assert!(validate_proxy_url(&Url::parse("http://localhost:8080").unwrap()).is_ok());
        assert!(validate_proxy_url(&Url::parse("http://[::1]:8080").unwrap()).is_ok());

        assert!(validate_proxy_url(&Url::parse("http://proxy.example.com").unwrap()).is_err());
        assert!(
            validate_proxy_url(&Url::parse("https://user:pass@proxy.example.com").unwrap())
                .is_err()
        );
        assert!(
            validate_proxy_url(&Url::parse("https://user@proxy.example.com").unwrap()).is_err()
        );
        assert!(validate_proxy_url(&Url::parse("ftp://proxy.example.com").unwrap()).is_err());
    }

    #[test]
    fn test_join_proxy_endpoint() {
        let base = Url::parse("https://proxy.example.com/edge?foo=1#frag").unwrap();
        let joined = join_proxy_endpoint(&base, "api/v1/test").unwrap();
        assert_eq!(
            joined.as_str(),
            "https://proxy.example.com/edge/api/v1/test"
        );
        assert!(
            join_proxy_endpoint(
                &Url::parse("http://proxy.example.com").unwrap(),
                "api/v1/test"
            )
            .is_err()
        );
    }
}
