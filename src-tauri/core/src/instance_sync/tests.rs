use sqlx::SqlitePool;

use super::{apply_device_config, SyncSummary};
use crate::{
    database::models::{
        instance::Instance,
        location::{Location, LocationMfaMethod},
        Id,
    },
    error::Error,
    proto::client_types::{DeviceConfig, DeviceConfigResponse, InstanceInfo},
};

fn info(name: &str) -> InstanceInfo {
    InstanceInfo {
        id: "instance-uuid".into(),
        name: name.into(),
        url: "https://xguard.local".into(),
        proxy_url: "https://edge.xguard.local".into(),
        username: "alice".into(),
        ..InstanceInfo::default()
    }
}

fn config(network_id: Id, name: &str, endpoint: &str) -> DeviceConfig {
    DeviceConfig {
        network_id,
        network_name: name.into(),
        endpoint: endpoint.into(),
        assigned_ip: "10.0.0.2/24".into(),
        pubkey: "server-key".into(),
        allowed_ips: "10.0.0.0/24".into(),
        keepalive_interval: 25,
        ..DeviceConfig::default()
    }
}

fn response(name: &str, configs: Vec<DeviceConfig>, token: Option<&str>) -> DeviceConfigResponse {
    DeviceConfigResponse {
        instance: Some(info(name)),
        configs,
        token: token.map(Into::into),
        ..DeviceConfigResponse::default()
    }
}

async fn setup(pool: &SqlitePool, configs: Vec<DeviceConfig>) -> Instance<Id> {
    let mut instance = Instance::from(info("office"));
    instance.token = Some("token-1".into());
    let instance = instance.save(pool).await.unwrap();
    for config in configs {
        crate::into_location(config, instance.id)
            .save(pool)
            .await
            .unwrap();
    }
    instance
}

async fn apply(
    pool: &SqlitePool,
    instance: &mut Instance<Id>,
    response: DeviceConfigResponse,
) -> Result<SyncSummary, Error> {
    let mut tx = pool.begin().await.unwrap();
    let result = apply_device_config(&mut tx, instance, response).await;
    tx.commit().await.unwrap();
    result
}

async fn locations(pool: &SqlitePool, instance: &Instance<Id>) -> Vec<Location<Id>> {
    let mut locations = Location::find_by_instance_id(pool, instance.id, true)
        .await
        .unwrap();
    locations.sort_by_key(|location| location.network_id);
    locations
}

#[sqlx::test(migrations = "../migrations")]
async fn test_identical_config_writes_nothing(pool: SqlitePool) {
    let mut instance = setup(&pool, vec![config(1, "hq", "hq:51820")]).await;

    let summary = apply(
        &pool,
        &mut instance,
        response("office", vec![config(1, "hq", "hq:51820")], None),
    )
    .await
    .unwrap();

    assert_eq!(summary, SyncSummary::default());
    assert!(!summary.locations_changed());
}

#[sqlx::test(migrations = "../migrations")]
async fn test_adds_updates_and_removes_locations(pool: SqlitePool) {
    let mut instance = setup(
        &pool,
        vec![config(1, "hq", "hq:51820"), config(2, "lab", "lab:51820")],
    )
    .await;

    let summary = apply(
        &pool,
        &mut instance,
        response(
            "office",
            vec![config(1, "hq", "new-hq:51820"), config(3, "dc", "dc:51820")],
            None,
        ),
    )
    .await
    .unwrap();

    assert_eq!(
        summary,
        SyncSummary {
            instance_changed: false,
            added: 1,
            updated: 1,
            removed: 1
        }
    );
    let stored = locations(&pool, &instance).await;
    let ids: Vec<_> = stored
        .iter()
        .map(|l| (l.network_id, l.endpoint.as_str()))
        .collect();
    assert_eq!(ids, [(1, "new-hq:51820"), (3, "dc:51820")]);
}

#[sqlx::test(migrations = "../migrations")]
async fn test_update_keeps_local_preferences(pool: SqlitePool) {
    let mut instance = setup(&pool, vec![config(1, "hq", "hq:51820")]).await;
    let mut location = locations(&pool, &instance).await.remove(0);
    location.route_all_traffic = true;
    location.mfa_method = Some(LocationMfaMethod::Email);
    location.save(&pool).await.unwrap();

    apply(
        &pool,
        &mut instance,
        response("office", vec![config(1, "hq-renamed", "hq:51820")], None),
    )
    .await
    .unwrap();

    let stored = locations(&pool, &instance).await.remove(0);
    assert_eq!(
        stored.id, location.id,
        "local ID (and its stats) must survive"
    );
    assert_eq!(stored.name, "hq-renamed");
    assert!(stored.route_all_traffic);
    assert_eq!(stored.mfa_method, Some(LocationMfaMethod::Email));
}

#[sqlx::test(migrations = "../migrations")]
async fn test_instance_fields_and_token(pool: SqlitePool) {
    let mut instance = setup(&pool, Vec::new()).await;

    // A missing token leaves the stored one alone.
    let summary = apply(&pool, &mut instance, response("renamed", Vec::new(), None))
        .await
        .unwrap();
    assert!(summary.instance_changed);
    let stored = Instance::find_by_id(&pool, instance.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.name, "renamed");
    assert_eq!(stored.token.as_deref(), Some("token-1"));

    apply(
        &pool,
        &mut instance,
        response("renamed", Vec::new(), Some("token-2")),
    )
    .await
    .unwrap();
    let stored = Instance::find_by_id(&pool, instance.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.token.as_deref(), Some("token-2"));
}

#[sqlx::test(migrations = "../migrations")]
async fn test_rejects_config_for_another_instance(pool: SqlitePool) {
    let mut instance = setup(&pool, vec![config(1, "hq", "hq:51820")]).await;
    let mut other = response("office", Vec::new(), None);
    other.instance.as_mut().unwrap().id = "someone-else".into();

    let result = apply(&pool, &mut instance, other).await;

    assert!(matches!(result, Err(Error::InvalidInput(_))));
    assert_eq!(locations(&pool, &instance).await.len(), 1);
}

#[sqlx::test(migrations = "../migrations")]
async fn test_missing_instance_info_is_an_error(pool: SqlitePool) {
    let mut instance = setup(&pool, Vec::new()).await;
    let mut empty = response("office", Vec::new(), None);
    empty.instance = None;

    let result = apply(&pool, &mut instance, empty).await;

    assert!(matches!(result, Err(Error::ResourceNotFound(_))));
}

/// A refresh carries the administrator's client settings: the traffic policy, the tunnel switch
/// and the (group) client MTU. The user's routing preference is kept, but the policy decides
/// what is routed and the server MTU caps the local one.
#[sqlx::test(migrations = "../migrations")]
async fn test_refresh_applies_client_settings(pool: SqlitePool) {
    use crate::{
        database::models::instance::ClientTrafficPolicy,
        proto::client_types::ClientTrafficPolicy as WirePolicy,
    };

    let mut instance = setup(&pool, vec![config(1, "hq", "hq:51820")]).await;
    let mut location = locations(&pool, &instance).await.remove(0);
    location.route_all_traffic = true;
    location.save(&pool).await.unwrap();
    assert!(!Instance::tunnels_disabled(&pool).await.unwrap());

    let mut refreshed = response("office", vec![config(1, "hq", "hq:51820")], None);
    let info = refreshed.instance.as_mut().unwrap();
    info.client_traffic_policy = Some(WirePolicy::DisableAllTraffic as i32);
    info.disable_tunnels = Some(true);
    refreshed.configs[0].mtu = Some(1280);
    let summary = apply(&pool, &mut instance, refreshed).await.unwrap();
    assert!(summary.instance_changed);

    let stored = Instance::find_by_id(&pool, instance.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.client_traffic_policy,
        ClientTrafficPolicy::DisableAllTraffic
    );
    assert!(Instance::tunnels_disabled(&pool).await.unwrap());

    let location = locations(&pool, &instance).await.remove(0);
    assert!(location.route_all_traffic, "the preference is kept");
    assert!(
        !location
            .effective_route_all_traffic(&pool, None)
            .await
            .unwrap(),
        "but the policy decides"
    );
    assert!(
        !location
            .effective_route_all_traffic(&pool, Some(true))
            .await
            .unwrap(),
        "also against an explicit request"
    );
    assert_eq!(location.client_mtu, Some(1280));
    assert_eq!(location.effective_mtu(Some(1420)), Some(1280));
    assert!(
        Location::update_routing(&pool, location.id, true)
            .await
            .is_err(),
        "routing all traffic cannot be switched on"
    );

    // Forcing all traffic works the other way round.
    let mut refreshed = response("office", vec![config(1, "hq", "hq:51820")], None);
    refreshed.instance.as_mut().unwrap().client_traffic_policy =
        Some(WirePolicy::ForceAllTraffic as i32);
    apply(&pool, &mut instance, refreshed).await.unwrap();
    let location = locations(&pool, &instance).await.remove(0);
    assert!(location
        .effective_route_all_traffic(&pool, Some(false))
        .await
        .unwrap());
    assert!(!Instance::tunnels_disabled(&pool).await.unwrap());
}
