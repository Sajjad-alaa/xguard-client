use std::collections::{HashMap, HashSet};

use serde_json::json;
use sqlx::SqlitePool;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header_exists, method, path},
};

use super::*;
use crate::{
    database::models::location::ServiceLocationMode,
    proto::client_types::{DeviceConfig, InstanceInfo},
};

#[test]
fn poll_url_requires_tls_except_loopback() {
    assert_eq!(
        poll_url("https://edge.example.com").unwrap().as_str(),
        "https://edge.example.com/api/v1/poll"
    );
    assert_eq!(
        poll_url("https://edge.example.com/base?x=1#y")
            .unwrap()
            .as_str(),
        "https://edge.example.com/base/api/v1/poll"
    );
    assert!(poll_url("http://127.0.0.1:8080").is_ok());
    assert!(poll_url("http://[::1]:8080").is_ok());
    assert!(poll_url("http://localhost:8080").is_ok());
    for refused in [
        "http://edge.example.com",
        "http://10.0.0.1",
        "ftp://edge.example.com",
        "https://user:pass@edge.example.com",
        "not a url",
        "file:///etc/passwd",
    ] {
        assert!(
            matches!(poll_url(refused), Err(PollError::InvalidUrl(_))),
            "{refused}"
        );
    }
}

#[test]
fn parses_not_modified_and_changed_responses() {
    let poll = parse_poll_response(
        br#"{"config_revision":"x1-a","not_modified":true,"poll_interval_secs":90}"#,
    )
    .unwrap();
    assert!(matches!(poll.outcome, PollOutcome::NotModified));
    assert_eq!(poll.revision.as_deref(), Some("x1-a"));
    assert_eq!(poll.interval, Some(Duration::from_secs(90)));

    let poll = parse_poll_response(
        br#"{"device_config":{"configs":[],"instance":null,"device":null},"config_revision":"x1-b"}"#,
    )
    .unwrap();
    assert!(matches!(poll.outcome, PollOutcome::Changed(_)));

    // Older Cores: no revision, no flag, just the configuration.
    let poll = parse_poll_response(br#"{"device_config":{"configs":[]}}"#).unwrap();
    assert!(matches!(poll.outcome, PollOutcome::Changed(_)));
    assert!(poll.revision.is_none());

    // An oversized revision is dropped rather than echoed back.
    let long = format!(
        r#"{{"config_revision":"{}","not_modified":true}}"#,
        "a".repeat(500)
    );
    assert!(
        parse_poll_response(long.as_bytes())
            .unwrap()
            .revision
            .is_none()
    );

    assert!(matches!(
        parse_poll_response(br#"{"not_modified":false}"#),
        Err(PollError::Server(_))
    ));
    assert!(matches!(
        parse_poll_response(b"garbage"),
        Err(PollError::Server(_))
    ));
}

#[test]
fn status_codes_map_to_errors() {
    assert_eq!(
        status_error(StatusCode::UNAUTHORIZED),
        PollError::Unauthorized
    );
    assert_eq!(status_error(StatusCode::FORBIDDEN), PollError::Forbidden);
    assert_eq!(
        status_error(StatusCode::TOO_MANY_REQUESTS),
        PollError::RateLimited
    );
    assert_eq!(
        status_error(StatusCode::PRECONDITION_REQUIRED),
        PollError::Unsupported
    );
    assert_eq!(
        status_error(StatusCode::PAYMENT_REQUIRED),
        PollError::Unsupported
    );
    assert!(matches!(
        status_error(StatusCode::FOUND),
        PollError::Server(_)
    ));
}

#[test]
fn schedule_uses_server_interval_within_bounds() {
    let mut schedule = SyncSchedule::default();
    // Middle of the jitter range: no jitter.
    assert_eq!(
        schedule.next_delay(Attempt::Succeeded(Some(Duration::from_secs(120))), 0.5),
        Duration::from_secs(120)
    );
    assert_eq!(
        schedule.next_delay(Attempt::Succeeded(Some(Duration::from_secs(1))), 0.5),
        MIN_INTERVAL
    );
    assert_eq!(
        schedule.next_delay(Attempt::Succeeded(Some(Duration::from_secs(99_999))), 0.5),
        MAX_INTERVAL
    );
    assert_eq!(
        schedule.next_delay(Attempt::Succeeded(None), 0.5),
        DEFAULT_INTERVAL
    );
}

#[test]
fn schedule_backs_off_and_recovers() {
    let mut schedule = SyncSchedule::default();
    let delays: Vec<_> = (0..8)
        .map(|_| schedule.next_delay(Attempt::Failed, 0.5).as_secs())
        .collect();
    assert_eq!(delays, [30, 60, 120, 240, 480, 960, 1800, 1800]);
    assert_eq!(schedule.consecutive_failures(), 8);
    assert_eq!(
        schedule.next_delay(Attempt::Succeeded(None), 0.5),
        DEFAULT_INTERVAL
    );
    assert_eq!(schedule.consecutive_failures(), 0);

    assert!(schedule.next_delay(Attempt::RateLimited, 0.5) >= DEFAULT_INTERVAL * 2);
    assert_eq!(schedule.next_delay(Attempt::Rejected, 0.5), REJECTED_DELAY);
}

#[test]
fn schedule_jitter_stays_within_twenty_percent() {
    let mut schedule = SyncSchedule::default();
    let low = schedule.next_delay(Attempt::Succeeded(Some(Duration::from_secs(100))), 0.0);
    let high = schedule.next_delay(
        Attempt::Succeeded(Some(Duration::from_secs(100))),
        0.999_999,
    );
    assert_eq!(low, Duration::from_secs(80));
    assert!(high > Duration::from_secs(119) && high <= Duration::from_secs(120));
    for _ in 0..100 {
        let unit = jitter_unit();
        assert!((0.0..1.0).contains(&unit));
    }
}

#[test]
fn attempt_classification() {
    let ok: Result<(), PollError> = Ok(());
    assert_eq!(
        Attempt::from_result(&ok, Some(Duration::from_secs(5))),
        Attempt::Succeeded(Some(Duration::from_secs(5)))
    );
    for (error, attempt) in [
        (PollError::RateLimited, Attempt::RateLimited),
        (PollError::Unauthorized, Attempt::Rejected),
        (PollError::Forbidden, Attempt::Rejected),
        (PollError::Unsupported, Attempt::Rejected),
        (PollError::Network("down".into()), Attempt::Failed),
        (PollError::Server("500".into()), Attempt::Failed),
    ] {
        assert_eq!(Attempt::from_result::<()>(&Err(error), None), attempt);
    }
}

fn location(id: Id, mfa: LocationMfaMode, service: ServiceLocationMode) -> Location<Id> {
    Location {
        id,
        instance_id: 1,
        network_id: id,
        name: format!("l{id}"),
        address: "10.0.0.2/24".into(),
        pubkey: "k".into(),
        endpoint: "e:1".into(),
        allowed_ips: "10.0.0.0/24".into(),
        dns: None,
        route_all_traffic: false,
        keepalive_interval: 25,
        location_mfa_mode: mfa,
        service_location_mode: service,
        mfa_method: None,
        posture_check_required: false,
        mfa_steps: sqlx::types::Json::default(),
        mfa_step_plan: sqlx::types::Json::default(),
        client_mtu: None,
    }
}

#[test]
fn plans_actions_for_live_tunnels_only() {
    let after: HashMap<Id, Location<Id>> = [
        location(1, LocationMfaMode::Disabled, ServiceLocationMode::Disabled),
        location(2, LocationMfaMode::Internal, ServiceLocationMode::Disabled),
        location(3, LocationMfaMode::Disabled, ServiceLocationMode::AlwaysOn),
        location(4, LocationMfaMode::Disabled, ServiceLocationMode::Disabled),
    ]
    .into_iter()
    .map(|l| (l.id, l))
    .collect();
    let summary = SyncSummary {
        removed_ids: vec![9],
        tunnel_changed_ids: vec![1, 2, 5],
        ..SyncSummary::default()
    };
    // 4 is unchanged, 5 changed but not connected, 42 belongs to another instance.
    let active: HashSet<Id> = [1, 2, 3, 4, 9, 42].into_iter().collect();

    assert_eq!(
        plan_tunnel_actions(&summary, &active, &after),
        [
            TunnelAction::Reconnect(1),
            TunnelAction::ReconnectByUser(2),
            TunnelAction::Disconnect(3),
            TunnelAction::Disconnect(9),
        ]
    );

    // A traffic policy change affects every live tunnel of the instance.
    let policy = SyncSummary {
        traffic_policy_changed: true,
        ..SyncSummary::default()
    };
    let active: HashSet<Id> = [4].into_iter().collect();
    assert_eq!(
        plan_tunnel_actions(&policy, &active, &after),
        [TunnelAction::Reconnect(4)]
    );
    assert!(plan_tunnel_actions(&SyncSummary::default(), &active, &after).is_empty());
}

fn wire_config(network_id: Id, endpoint: &str) -> DeviceConfig {
    DeviceConfig {
        network_id,
        network_name: format!("net{network_id}"),
        endpoint: endpoint.into(),
        assigned_ip: "10.0.0.2/24".into(),
        pubkey: "server-key".into(),
        allowed_ips: "10.0.0.0/24".into(),
        keepalive_interval: 25,
        ..DeviceConfig::default()
    }
}

fn wire_response(endpoint: &str) -> DeviceConfigResponse {
    DeviceConfigResponse {
        instance: Some(InstanceInfo {
            id: "instance-uuid".into(),
            name: "office".into(),
            url: "https://xguard.local".into(),
            proxy_url: "https://edge.xguard.local".into(),
            username: "alice".into(),
            ..InstanceInfo::default()
        }),
        configs: vec![wire_config(1, endpoint)],
        ..DeviceConfigResponse::default()
    }
}

/// Polls a mock Edge speaking the real JSON API: a full configuration is applied, the revision
/// is sent back next time and `not_modified` writes nothing, refusals are reported.
#[sqlx::test(migrations = "../migrations")]
async fn sync_instance_against_mock_edge(pool: SqlitePool) {
    let server = MockServer::start().await;
    let mut instance = Instance::from(wire_response("hq:51820").instance.unwrap());
    instance.proxy_url = server.uri();
    instance.token = Some("polling-token".into());
    let instance = instance.save(&pool).await.unwrap();
    forget_revision(instance.id);

    Mock::given(method("POST"))
        .and(path("/api/v1/poll"))
        .and(header_exists(CLIENT_VERSION_HEADER))
        .and(body_json(
            json!({"token": "polling-token", "config_revision": null}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "device_config": wire_response("hq:51820"),
            "config_revision": "x1-first",
            "not_modified": false,
            "poll_interval_secs": 120,
        })))
        .expect(1)
        .mount(&server)
        .await;
    let report = sync_instance(&pool, instance.id, &HashSet::new())
        .await
        .unwrap();
    assert!(report.changed());
    assert_eq!(report.summary.as_ref().unwrap().added, 1);
    assert_eq!(report.interval, Some(Duration::from_secs(120)));
    let stored = Location::find_by_instance_id(&pool, instance.id, true)
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    let location_id = stored[0].id;
    // The proxy URL the instance was enrolled with is replaced by the server's.
    server.reset().await;

    // The stored instance now points at the server's proxy URL; point it back at the mock.
    let mut current = Instance::find_by_id(&pool, instance.id)
        .await
        .unwrap()
        .unwrap();
    current.proxy_url = server.uri();
    current.save(&pool).await.unwrap();

    Mock::given(method("POST"))
        .and(path("/api/v1/poll"))
        .and(body_json(
            json!({"token": "polling-token", "config_revision": "x1-first"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "config_revision": "x1-first",
            "not_modified": true,
        })))
        .expect(1)
        .mount(&server)
        .await;
    let report = sync_instance(&pool, instance.id, &HashSet::new())
        .await
        .unwrap();
    assert!(report.summary.is_none());
    assert!(!report.changed());
    server.reset().await;

    // A changed endpoint reconnects the live tunnel.
    let mut changed = wire_response("new-hq:51820");
    changed.instance.as_mut().unwrap().proxy_url = server.uri();
    Mock::given(method("POST"))
        .and(path("/api/v1/poll"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "device_config": changed,
            "config_revision": "x1-second",
        })))
        .mount(&server)
        .await;
    let active: HashSet<Id> = [location_id].into_iter().collect();
    let report = sync_instance(&pool, instance.id, &active).await.unwrap();
    assert_eq!(report.actions, [TunnelAction::Reconnect(location_id)]);
    server.reset().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/poll"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"error": "unauthorized"})))
        .mount(&server)
        .await;
    assert!(matches!(
        sync_instance(&pool, instance.id, &HashSet::new()).await,
        Err(SyncError::Poll(PollError::Unauthorized))
    ));
    server.reset().await;

    // Redirects are not followed: the token must not travel to another host.
    Mock::given(method("POST"))
        .and(path("/api/v1/poll"))
        .respond_with(
            ResponseTemplate::new(307).insert_header("location", "https://evil.example/collect"),
        )
        .mount(&server)
        .await;
    assert!(matches!(
        sync_instance(&pool, instance.id, &HashSet::new()).await,
        Err(SyncError::Poll(PollError::Server(_)))
    ));
}

#[sqlx::test(migrations = "../migrations")]
async fn sync_instance_needs_a_token(pool: SqlitePool) {
    let mut instance = Instance::from(wire_response("hq:51820").instance.unwrap());
    instance.token = None;
    let instance = instance.save(&pool).await.unwrap();
    assert!(matches!(
        sync_instance(&pool, instance.id, &HashSet::new()).await,
        Err(SyncError::NoToken)
    ));
    assert!(matches!(
        sync_instance(&pool, instance.id + 100, &HashSet::new()).await,
        Err(SyncError::NotFound(_))
    ));
}

#[cfg(unix)]
#[test]
fn network_fingerprint_is_stable() {
    let first = network_fingerprint().expect("available on Unix");
    assert_eq!(network_fingerprint(), Some(first));
}

#[test]
fn policy_tightening_disconnects_mfa_tunnel() {
    use crate::database::models::location::{Location, LocationMfaMode};

    let make_loc = |id: Id, mfa: LocationMfaMode| Location {
        id,
        instance_id: 1,
        network_id: id,
        name: format!("loc-{id}"),
        address: "10.0.0.2/24".into(),
        pubkey: "k".into(),
        endpoint: "vpn.example.com:51820".into(),
        allowed_ips: "10.0.0.0/24".into(),
        dns: None,
        route_all_traffic: false,
        keepalive_interval: 25,
        location_mfa_mode: mfa,
        service_location_mode: ServiceLocationMode::Disabled,
        mfa_method: None,
        posture_check_required: false,
        mfa_steps: Default::default(),
        mfa_step_plan: Default::default(),
        client_mtu: None,
    };

    let active: HashSet<Id> = [1, 2].into();
    let after: HashMap<Id, _> = [
        make_loc(1, LocationMfaMode::Internal),
        make_loc(2, LocationMfaMode::Disabled),
    ]
    .into_iter()
    .map(|l| (l.id, l))
    .collect();

    let tightened = SyncSummary {
        policy_tightened_ids: vec![1],
        tunnel_changed_ids: vec![1],
        ..SyncSummary::default()
    };
    assert_eq!(
        plan_tunnel_actions(&tightened, &active, &after),
        [TunnelAction::DisconnectForPolicy(1)]
    );

    let policy_changed = SyncSummary {
        traffic_policy_changed: true,
        ..SyncSummary::default()
    };
    let mut actions = plan_tunnel_actions(&policy_changed, &active, &after);
    actions.sort_by_key(|a| match a {
        TunnelAction::Disconnect(id)
        | TunnelAction::DisconnectForPolicy(id)
        | TunnelAction::Reconnect(id)
        | TunnelAction::ReconnectByUser(id) => *id,
    });
    assert_eq!(
        actions,
        [
            TunnelAction::DisconnectForPolicy(1),
            TunnelAction::Reconnect(2),
        ]
    );
}
