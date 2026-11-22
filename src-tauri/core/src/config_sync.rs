//! Configuration sync: keeps enrolled instances in line with XGuard without a new enrollment.
//!
//! The client polls Edge (`POST /api/v1/poll`) with the instance's polling token and the
//! revision it applied last. Edge forwards to Core, which answers either `not_modified` (one small
//! response, nothing written locally) or the full device configuration, applied with
//! [`apply_device_config`] in one transaction.
//!
//! Callers (the desktop app's background task, the CLIs) decide when to poll; [`SyncSchedule`]
//! computes the delay with the server's suggested interval, exponential backoff on errors and
//! jitter, so many clients do not poll in lockstep. [`plan_tunnel_actions`] decides what live
//! tunnels need after a change.
//!
//! Security: requests go only to an HTTPS Edge URL (plain HTTP only to loopback), redirects are
//! never followed (the token must not leak to another host), responses are size-limited, and the
//! token is never logged.

use std::{
    collections::{HashMap, HashSet},
    hash::{BuildHasher, Hasher},
    net::IpAddr,
    sync::{LazyLock, Mutex},
    time::Duration,
};

use reqwest::{Client, StatusCode, Url, redirect::Policy};

use crate::{
    database::{
        DbPool,
        models::{
            Id,
            instance::Instance,
            location::{Location, LocationMfaMode},
        },
    },
    error::Error,
    instance_sync::{SyncSummary, apply_device_config},
    proto::client_types::{DeviceConfigResponse, InstanceInfoRequest, InstanceInfoResponse},
    proxy::construct_platform_header,
    version::{CLIENT_PLATFORM_HEADER, CLIENT_VERSION_HEADER, PKG_VERSION},
};

/// Interval used when the server suggests none.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(60);
/// Bounds applied to the server's suggestion.
pub const MIN_INTERVAL: Duration = Duration::from_secs(30);
pub const MAX_INTERVAL: Duration = Duration::from_secs(3600);
/// First retry delay after a failure; doubles per consecutive failure up to [`BACKOFF_MAX`].
pub const BACKOFF_START: Duration = Duration::from_secs(30);
pub const BACKOFF_MAX: Duration = Duration::from_secs(1800);
/// Delay after the server refused the device (unknown token, disabled user) or does not serve
/// configuration polling: nothing will change soon, so ask rarely.
pub const REJECTED_DELAY: Duration = Duration::from_secs(3600);
/// Jitter applied to every delay: +/- this fraction.
const JITTER_FRACTION: f64 = 0.2;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound on a configuration response.
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Longest revision kept from a server response.
const MAX_REVISION_LENGTH: usize = 128;

/// No redirects: a redirect could send the polling token to another host.
static POLL_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    Client::builder()
        .redirect(Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .build()
        .unwrap_or_else(|err| {
            error!("Failed to build the configuration sync HTTP client: {err}");
            Client::new()
        })
});

/// Revisions applied last, per instance. Kept in memory: after a restart the first poll fetches
/// the full configuration once.
static REVISIONS: LazyLock<Mutex<HashMap<Id, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn revisions() -> std::sync::MutexGuard<'static, HashMap<Id, String>> {
    REVISIONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Forgets the stored revision, so the next poll fetches the full configuration.
pub fn forget_revision(instance_id: Id) {
    revisions().remove(&instance_id);
}

/// Why a poll did not produce a configuration.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PollError {
    #[error("the server does not serve configuration polling")]
    Unsupported,
    #[error("the server does not know this device's polling token")]
    Unauthorized,
    #[error("the server refused the device (for example, the user is disabled)")]
    Forbidden,
    #[error("polling too often")]
    RateLimited,
    #[error("refusing to poll {0}")]
    InvalidUrl(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("unexpected server response: {0}")]
    Server(String),
}

/// Result of one successful poll.
#[derive(Debug)]
pub enum PollOutcome {
    NotModified,
    Changed(Box<DeviceConfigResponse>),
}

#[derive(Debug)]
pub struct Poll {
    pub outcome: PollOutcome,
    pub revision: Option<String>,
    pub interval: Option<Duration>,
}

/// The poll endpoint of an Edge URL: HTTPS, or HTTP to a loopback address; no credentials.
pub fn poll_url(proxy_url: &str) -> Result<Url, PollError> {
    let mut url = Url::parse(proxy_url).map_err(|_| PollError::InvalidUrl(proxy_url.into()))?;
    let loopback = match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
        Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
        None => return Err(PollError::InvalidUrl(proxy_url.into())),
    };
    let secure = url.scheme() == "https" || (url.scheme() == "http" && loopback);
    if !secure || !url.username().is_empty() || url.password().is_some() {
        return Err(PollError::InvalidUrl(proxy_url.into()));
    }
    url.set_query(None);
    url.set_fragment(None);
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    url.join("api/v1/poll")
        .map_err(|_| PollError::InvalidUrl(proxy_url.into()))
}

/// Interprets an Edge response body for a 200 status.
pub fn parse_poll_response(body: &[u8]) -> Result<Poll, PollError> {
    let response: InstanceInfoResponse =
        serde_json::from_slice(body).map_err(|err| PollError::Server(err.to_string()))?;
    let revision = response
        .config_revision
        .filter(|revision| !revision.is_empty() && revision.len() <= MAX_REVISION_LENGTH);
    let interval = response
        .poll_interval_secs
        .map(|secs| Duration::from_secs(u64::from(secs)));
    let outcome = if response.not_modified == Some(true) {
        PollOutcome::NotModified
    } else {
        PollOutcome::Changed(Box::new(response.device_config.ok_or_else(|| {
            PollError::Server("response without a configuration".into())
        })?))
    };
    Ok(Poll {
        outcome,
        revision,
        interval,
    })
}

fn status_error(status: StatusCode) -> PollError {
    match status {
        StatusCode::UNAUTHORIZED => PollError::Unauthorized,
        StatusCode::FORBIDDEN => PollError::Forbidden,
        StatusCode::TOO_MANY_REQUESTS => PollError::RateLimited,
        // 428: Cores without config sync; 402: pre-fork servers without the feature.
        StatusCode::PRECONDITION_REQUIRED | StatusCode::PAYMENT_REQUIRED => PollError::Unsupported,
        status if status.is_redirection() => {
            PollError::Server(format!("refused to follow a redirect ({status})"))
        }
        status => PollError::Server(format!("HTTP {status}")),
    }
}

/// Polls Edge for the configuration of the device identified by `token`.
pub async fn fetch_config(
    proxy_url: &str,
    token: &str,
    revision: Option<&str>,
) -> Result<Poll, PollError> {
    let url = poll_url(proxy_url)?;
    let request = InstanceInfoRequest {
        token: token.to_owned(),
        config_revision: revision.map(str::to_owned),
    };
    let mut response = POLL_CLIENT
        .post(url)
        .json(&request)
        .header(CLIENT_VERSION_HEADER, PKG_VERSION)
        .header(CLIENT_PLATFORM_HEADER, construct_platform_header())
        .timeout(REQUEST_TIMEOUT)
        .send()
        .await
        .map_err(|err| PollError::Network(err.without_url().to_string()))?;
    let status = response.status();
    if status != StatusCode::OK {
        return Err(status_error(status));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(PollError::Server("response too large".into()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| PollError::Network(err.without_url().to_string()))?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(PollError::Server("response too large".into()));
        }
        body.extend_from_slice(&chunk);
    }
    parse_poll_response(&body)
}

/// What happened to a poll, as far as scheduling is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attempt {
    /// Answered; the server may suggest an interval.
    Succeeded(Option<Duration>),
    /// Network or server error: retry with backoff.
    Failed,
    /// The server asked us to slow down.
    RateLimited,
    /// The server refused the device or does not serve polling.
    Rejected,
}

impl Attempt {
    #[must_use]
    pub fn from_result<T>(result: &Result<T, PollError>, interval: Option<Duration>) -> Self {
        match result {
            Ok(_) => Self::Succeeded(interval),
            Err(PollError::RateLimited) => Self::RateLimited,
            Err(PollError::Unauthorized | PollError::Forbidden | PollError::Unsupported) => {
                Self::Rejected
            }
            Err(PollError::InvalidUrl(_)) => Self::Rejected,
            Err(PollError::Network(_) | PollError::Server(_)) => Self::Failed,
        }
    }
}

/// Per-instance poll timing with backoff and jitter. Pure, so it is easy to test.
#[derive(Debug, Default)]
pub struct SyncSchedule {
    consecutive_failures: u32,
}

impl SyncSchedule {
    /// Delay until the next poll after `attempt`. `jitter_unit` is a value in `[0, 1)`.
    pub fn next_delay(&mut self, attempt: Attempt, jitter_unit: f64) -> Duration {
        let base = match attempt {
            Attempt::Succeeded(interval) => {
                self.consecutive_failures = 0;
                interval
                    .unwrap_or(DEFAULT_INTERVAL)
                    .clamp(MIN_INTERVAL, MAX_INTERVAL)
            }
            Attempt::Failed => {
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                self.backoff()
            }
            Attempt::RateLimited => {
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                self.backoff().max(DEFAULT_INTERVAL * 2)
            }
            Attempt::Rejected => {
                self.consecutive_failures = 0;
                REJECTED_DELAY
            }
        };
        let factor = 1.0 - JITTER_FRACTION + 2.0 * JITTER_FRACTION * jitter_unit.clamp(0.0, 1.0);
        base.mul_f64(factor).max(Duration::from_secs(1))
    }

    fn backoff(&self) -> Duration {
        let exponent = self.consecutive_failures.saturating_sub(1).min(16);
        BACKOFF_START
            .saturating_mul(1u32 << exponent)
            .min(BACKOFF_MAX)
    }

    #[must_use]
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }
}

/// A value in `[0, 1)` for jitter. Not cryptographic; only spreads polls out.
#[must_use]
pub fn jitter_unit() -> f64 {
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    #[allow(clippy::cast_precision_loss)]
    let unit = (hasher.finish() >> 11) as f64 / (1u64 << 53) as f64;
    unit
}

/// A digest of this machine's interface addresses: when it changes, the network changed
/// (new Wi-Fi, cable, VPN of another vendor) and a poll is worth doing now. Interfaces of XGuard
/// tunnels are left out, so connecting does not count as a network change. `None` where not
/// available (Windows).
#[must_use]
pub fn network_fingerprint() -> Option<u64> {
    #[cfg(unix)]
    {
        let mut entries: Vec<String> = nix::ifaddrs::getifaddrs()
            .ok()?
            .filter(|ifaddr| {
                let name = &ifaddr.interface_name;
                !["wg", "xgs", "utun"]
                    .iter()
                    .any(|prefix| name.starts_with(prefix))
            })
            .filter_map(|ifaddr| {
                let address = ifaddr.address?;
                let ip = address
                    .as_sockaddr_in()
                    .map(|v4| IpAddr::V4(v4.ip()))
                    .or_else(|| address.as_sockaddr_in6().map(|v6| IpAddr::V6(v6.ip())))?;
                (!ip.is_loopback()).then(|| format!("{}={ip}", ifaddr.interface_name))
            })
            .collect();
        entries.sort();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(&entries, &mut hasher);
        Some(hasher.finish())
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// What a live tunnel needs after a configuration change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelAction {
    /// The location is gone, or became a service location the background service runs now.
    Disconnect(Id),
    /// The tunnel settings changed and the location needs no user interaction to connect.
    Reconnect(Id),
    /// The tunnel settings changed but connecting needs the user (MFA): ask them to reconnect.
    ReconnectByUser(Id),
}

/// Decides what each active location of the synced instance needs.
///
/// `active` may contain locations of other instances; they are ignored. `after` holds the
/// instance's locations as stored after the sync.
#[must_use]
pub fn plan_tunnel_actions(
    summary: &SyncSummary,
    active: &HashSet<Id>,
    after: &HashMap<Id, Location<Id>>,
) -> Vec<TunnelAction> {
    let mut active: Vec<Id> = active.iter().copied().collect();
    active.sort_unstable();
    let mut actions = Vec::new();
    for id in active {
        if summary.removed_ids.contains(&id) {
            actions.push(TunnelAction::Disconnect(id));
            continue;
        }
        let Some(location) = after.get(&id) else {
            continue;
        };
        if location.service_location_mode
            != crate::database::models::location::ServiceLocationMode::Disabled
        {
            actions.push(TunnelAction::Disconnect(id));
        } else if summary.tunnel_changed_ids.contains(&id) || summary.traffic_policy_changed {
            // Posture-only locations reconnect on their own (the check needs no user); MFA does.
            if location.location_mfa_mode != LocationMfaMode::Disabled {
                actions.push(TunnelAction::ReconnectByUser(id));
            } else {
                actions.push(TunnelAction::Reconnect(id));
            }
        }
    }
    actions
}

/// Why an instance could not be synced.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("instance {0} not found")]
    NotFound(Id),
    #[error("instance has no polling token")]
    NoToken,
    #[error(transparent)]
    Poll(#[from] PollError),
    #[error(transparent)]
    Local(#[from] Error),
}

impl From<sqlx::Error> for SyncError {
    fn from(err: sqlx::Error) -> Self {
        Self::Local(err.into())
    }
}

/// Result of [`sync_instance`].
#[derive(Debug, Default)]
pub struct SyncReport {
    pub instance_id: Id,
    pub instance_name: String,
    /// `None` when the configuration was unchanged.
    pub summary: Option<SyncSummary>,
    pub actions: Vec<TunnelAction>,
    pub interval: Option<Duration>,
    /// Post-commit locations for re-planning after checking live tunnel state.
    pub after_locations: HashMap<Id, Location<Id>>,
}

impl SyncReport {
    #[must_use]
    pub fn changed(&self) -> bool {
        self.summary
            .as_ref()
            .is_some_and(|summary| summary.instance_changed || summary.locations_changed())
    }
}

/// Polls and applies the configuration of one instance.
///
/// `active` lists the locations with a live tunnel; the report says what they need. Applying the
/// actions (and pushing service locations to the background service) is up to the caller.
pub async fn sync_instance(
    pool: &DbPool,
    instance_id: Id,
    active: &HashSet<Id>,
) -> Result<SyncReport, SyncError> {
    let instance = Instance::find_by_id(pool, instance_id)
        .await?
        .ok_or(SyncError::NotFound(instance_id))?;
    let Some(token) = instance.token.clone() else {
        return Err(SyncError::NoToken);
    };
    let known = revisions().get(&instance_id).cloned();
    let poll = fetch_config(&instance.proxy_url, &token, known.as_deref()).await?;
    let mut report = SyncReport {
        instance_id,
        instance_name: instance.name.clone(),
        interval: poll.interval,
        ..SyncReport::default()
    };
    let config = match poll.outcome {
        PollOutcome::NotModified => {
            if let Some(revision) = poll.revision {
                revisions().insert(instance_id, revision);
            }
            return Ok(report);
        }
        PollOutcome::Changed(config) => config,
    };

    let mut transaction = pool.begin().await?;
    let Some(mut instance) = Instance::find_by_id(&mut *transaction, instance_id).await? else {
        return Err(SyncError::NotFound(instance_id));
    };
    let summary = apply_device_config(&mut transaction, &mut instance, *config).await?;
    let after: HashMap<Id, Location<Id>> =
        Location::find_by_instance_id(&mut *transaction, instance_id, true)
            .await?
            .into_iter()
            .map(|location| (location.id, location))
            .collect();
    transaction.commit().await?;
    report.instance_name = instance.name;
    match poll.revision {
        Some(revision) => {
            revisions().insert(instance_id, revision);
        }
        None => forget_revision(instance_id),
    }

    report.actions = plan_tunnel_actions(&summary, active, &after);
    report.after_locations = after;
    report.summary = Some(summary);
    Ok(report)
}

#[cfg(test)]
mod tests;
