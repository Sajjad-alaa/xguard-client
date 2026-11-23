//! New client version check, against the GitHub releases of xguard-client.
//!
//! - At most one request per day per running client: results (also "nothing found") are cached
//!   for [`CHECK_INTERVAL`]. 10 s timeout, at most 1 MiB read, no redirects.
//! - Failures are expected (no internet access, no release published yet: GitHub answers 404),
//!   so they are logged at debug level only and the check simply reports no update.
//! - Only published releases count: `/releases/latest` never returns drafts or pre-releases.

use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use reqwest::{StatusCode, header};
use semver::Version;
use serde::{Deserialize, Serialize};

/// GitHub API endpoint for the newest published xguard-client release.
pub const LATEST_RELEASE_URL: &str =
    "https://api.github.com/repos/Sajjad-alaa/xguard-client/releases/latest";
/// How long one check result is reused.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_NOTES_CHARS: usize = 20_000;
const MAX_SUMMARY_CHARS: usize = 300;

/// A newer release, as the UI shows it.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AppVersionInfo {
    pub version: String,
    pub release_date: String,
    pub release_notes_url: String,
    pub update_url: String,
    pub summary: Option<String>,
    pub notes: Option<String>,
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    published_at: Option<DateTime<Utc>>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

/// Why no release information is available. All expected in normal operation.
#[derive(Debug, thiserror::Error)]
pub enum UpdateCheckError {
    #[error("no release has been published yet")]
    NoRelease,
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("unexpected HTTP status {0}")]
    Status(StatusCode),
    #[error("response is larger than {MAX_RESPONSE_BYTES} bytes")]
    TooLarge,
    #[error("invalid release data: {0}")]
    Invalid(String),
}

fn parse_version(value: &str) -> Result<Version, UpdateCheckError> {
    let value = value.trim();
    Version::parse(value.strip_prefix(['v', 'V']).unwrap_or(value))
        .map_err(|err| UpdateCheckError::Invalid(format!("version {value:?}: {err}")))
}

/// Same ordering as Core: pre-release and build suffixes are ignored, so a 2.2.0-beta build is
/// not told to "update" to 2.2.0.
fn is_newer(current: &Version, candidate: &Version) -> bool {
    (candidate.major, candidate.minor, candidate.patch)
        > (current.major, current.minor, current.patch)
}

/// The release in `body`, or `None` for drafts and pre-releases.
fn parse_release(body: &[u8]) -> Result<Option<(Version, AppVersionInfo)>, UpdateCheckError> {
    let release: GithubRelease =
        serde_json::from_slice(body).map_err(|err| UpdateCheckError::Invalid(err.to_string()))?;
    if release.draft || release.prerelease {
        return Ok(None);
    }
    let version = parse_version(&release.tag_name)?;
    if !release.html_url.starts_with("https://") {
        return Err(UpdateCheckError::Invalid(format!(
            "release URL {:?} is not https",
            release.html_url
        )));
    }
    let notes: Option<String> = release
        .body
        .map(|body| body.chars().take(MAX_NOTES_CHARS).collect())
        .filter(|notes: &String| !notes.trim().is_empty());
    let summary = notes.as_deref().and_then(|notes| {
        notes
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.chars().take(MAX_SUMMARY_CHARS).collect())
    });
    let info = AppVersionInfo {
        version: version.to_string(),
        release_date: release
            .published_at
            .map(|date| date.date_naive().to_string())
            .unwrap_or_default(),
        release_notes_url: release.html_url.clone(),
        update_url: release.html_url,
        summary,
        notes,
    };
    Ok(Some((version, info)))
}

async fn fetch_latest_release(
    url: &str,
) -> Result<Option<(Version, AppVersionInfo)>, UpdateCheckError> {
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("xguard-client/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let mut response = client
        .get(url)
        .header(header::ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await?;
    match response.status() {
        StatusCode::OK => {}
        StatusCode::NOT_FOUND => return Err(UpdateCheckError::NoRelease),
        status => return Err(UpdateCheckError::Status(status)),
    }
    if response
        .content_length()
        .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
    {
        return Err(UpdateCheckError::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(UpdateCheckError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    parse_release(&body)
}

/// Asks `url` for the newest release and returns it when it is newer than `current_version`.
pub async fn check_for_update(
    url: &str,
    current_version: &str,
) -> Result<Option<AppVersionInfo>, UpdateCheckError> {
    let current = parse_version(current_version)?;
    Ok(fetch_latest_release(url)
        .await?
        .and_then(|(version, info)| is_newer(&current, &version).then_some(info)))
}

/// Caches one check result for [`CHECK_INTERVAL`].
pub struct UpdateChecker {
    url: String,
    interval: Duration,
    last: Mutex<Option<(Instant, Option<AppVersionInfo>)>>,
    /// Only one request at a time; callers arriving meanwhile get its result.
    in_flight: tokio::sync::Mutex<()>,
}

impl UpdateChecker {
    #[must_use]
    pub const fn new_const(url: String, interval: Duration) -> Self {
        Self {
            url,
            interval,
            last: Mutex::new(None),
            in_flight: tokio::sync::Mutex::const_new(()),
        }
    }

    fn cached(&self) -> Option<Option<AppVersionInfo>> {
        let last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        last.as_ref()
            .filter(|(at, _)| at.elapsed() < self.interval)
            .map(|(_, info)| info.clone())
    }

    /// The newer release, if any. Contacts the server at most once per interval; errors are
    /// logged at debug level and reported as "no update".
    pub async fn latest(&self, current_version: &str) -> Option<AppVersionInfo> {
        if let Some(cached) = self.cached() {
            return cached;
        }
        let _guard = self.in_flight.lock().await;
        if let Some(cached) = self.cached() {
            return cached;
        }
        debug!("Checking for a new XGuard client version at {}", self.url());
        let result = match check_for_update(self.url(), current_version).await {
            Ok(Some(info)) => {
                info!(
                    "XGuard client {} is available (released {}): {}",
                    info.version, info.release_date, info.update_url
                );
                Some(info)
            }
            Ok(None) => {
                debug!("The XGuard client is up to date ({current_version}).");
                None
            }
            Err(err) => {
                debug!("Could not check for a new XGuard client version: {err}");
                None
            }
        };
        *self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some((Instant::now(), result.clone()));
        result
    }
}

/// The checker the app uses: GitHub releases, once per day.
pub static UPDATE_CHECKER: UpdateChecker = UpdateChecker::new_const(String::new(), CHECK_INTERVAL);

impl UpdateChecker {
    fn url(&self) -> &str {
        if self.url.is_empty() {
            LATEST_RELEASE_URL
        } else {
            &self.url
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    use super::*;

    const RELEASE_PATH: &str = "/repos/Sajjad-alaa/xguard-client/releases/latest";

    fn release(tag: &str) -> serde_json::Value {
        json!({
            "html_url": format!("https://github.com/Sajjad-alaa/xguard-client/releases/tag/{tag}"),
            "tag_name": tag,
            "name": format!("XGuard client {tag}"),
            "draft": false,
            "prerelease": false,
            "published_at": "2026-11-21T10:00:00Z",
            "assets": [{"name": "xguard-client_x64.msi"}],
            "body": "## Changes\n\nFaster connections.\n- more",
        })
    }

    async fn server(response: ResponseTemplate, expected_calls: u64) -> (MockServer, String) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(RELEASE_PATH))
            .and(header("accept", "application/vnd.github+json"))
            .respond_with(response)
            .expect(expected_calls)
            .mount(&server)
            .await;
        let url = format!("{}{RELEASE_PATH}", server.uri());
        (server, url)
    }

    #[test]
    fn compares_versions_without_prerelease_suffixes() {
        let v = |s: &str| parse_version(s).unwrap();
        assert!(is_newer(&v("2.2.0"), &v("v2.2.1")));
        assert!(is_newer(&v("2.2.0-beta1"), &v("2.3.0")));
        assert!(!is_newer(&v("2.2.0"), &v("2.2.0")));
        assert!(!is_newer(&v("2.2.0-beta1"), &v("2.2.0")));
        assert!(!is_newer(&v("2.3.0"), &v("2.2.9")));
        assert!(parse_version("latest").is_err());
    }

    #[test]
    fn parses_release() {
        let body = serde_json::to_vec(&release("v2.3.0")).unwrap();
        let (version, info) = parse_release(&body).unwrap().unwrap();
        assert_eq!(version, Version::new(2, 3, 0));
        assert_eq!(
            info,
            AppVersionInfo {
                version: "2.3.0".into(),
                release_date: "2026-11-21".into(),
                release_notes_url:
                    "https://github.com/Sajjad-alaa/xguard-client/releases/tag/v2.3.0".into(),
                update_url: "https://github.com/Sajjad-alaa/xguard-client/releases/tag/v2.3.0"
                    .into(),
                summary: Some("Faster connections.".into()),
                notes: Some("## Changes\n\nFaster connections.\n- more".into()),
            }
        );
        let mut pre = release("v2.4.0-rc1");
        pre["prerelease"] = json!(true);
        assert!(
            parse_release(&serde_json::to_vec(&pre).unwrap())
                .unwrap()
                .is_none()
        );
        let mut bad = release("v2.4.0");
        bad["html_url"] = json!("javascript:alert(1)");
        assert!(parse_release(&serde_json::to_vec(&bad).unwrap()).is_err());
        assert!(parse_release(b"not json").is_err());
    }

    #[tokio::test]
    async fn reports_newer_release_only() {
        let (_server, url) = server(
            ResponseTemplate::new(200).set_body_json(release("v2.3.0")),
            2,
        )
        .await;
        let info = check_for_update(&url, "2.2.0").await.unwrap().unwrap();
        assert_eq!(info.version, "2.3.0");
        assert!(check_for_update(&url, "2.3.0").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn failures_are_errors_the_checker_turns_into_no_update() {
        let (_server, url) = server(ResponseTemplate::new(404), 1).await;
        assert!(matches!(
            check_for_update(&url, "2.2.0").await,
            Err(UpdateCheckError::NoRelease)
        ));
        let (_server, url) = server(
            ResponseTemplate::new(302).insert_header("location", "https://evil.example/"),
            1,
        )
        .await;
        assert!(matches!(
            check_for_update(&url, "2.2.0").await,
            Err(UpdateCheckError::Status(StatusCode::FOUND))
        ));
        let (_server, url) = server(
            ResponseTemplate::new(200).set_body_string("x".repeat(MAX_RESPONSE_BYTES + 1)),
            1,
        )
        .await;
        assert!(matches!(
            check_for_update(&url, "2.2.0").await,
            Err(UpdateCheckError::TooLarge)
        ));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/latest", listener.local_addr().unwrap());
        drop(listener);
        assert!(matches!(
            check_for_update(&url, "2.2.0").await,
            Err(UpdateCheckError::Request(_))
        ));
        let checker = UpdateChecker::new_const(url, CHECK_INTERVAL);
        assert_eq!(checker.latest("2.2.0").await, None);
    }

    #[tokio::test]
    async fn checker_contacts_the_server_once_per_interval() {
        // Exactly one request, however often the UI and the periodic task ask.
        let (_server, url) = server(
            ResponseTemplate::new(200).set_body_json(release("v2.3.0")),
            1,
        )
        .await;
        let checker = UpdateChecker::new_const(url, CHECK_INTERVAL);
        let (a, b) = tokio::join!(checker.latest("2.2.0"), checker.latest("2.2.0"));
        assert_eq!(a.as_ref().unwrap().version, "2.3.0");
        assert_eq!(a, b);
        assert_eq!(checker.latest("2.2.0").await, a);

        // "No release yet" is cached as well.
        let (_server, url) = server(ResponseTemplate::new(404), 1).await;
        let checker = UpdateChecker::new_const(url, CHECK_INTERVAL);
        assert_eq!(checker.latest("2.2.0").await, None);
        assert_eq!(checker.latest("2.2.0").await, None);

        // After the interval the server is asked again.
        let (_server, url) = server(
            ResponseTemplate::new(200).set_body_json(release("v2.3.0")),
            2,
        )
        .await;
        let checker = UpdateChecker::new_const(url, Duration::ZERO);
        checker.latest("2.2.0").await;
        checker.latest("2.2.0").await;
    }

    #[test]
    fn app_checker_uses_github() {
        assert_eq!(UPDATE_CHECKER.url(), LATEST_RELEASE_URL);
    }
}
