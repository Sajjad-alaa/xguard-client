//! Hands an instance's service locations to the background service.
//!
//! Service locations are tunnels the background service (running as root / `SYSTEM`) keeps up
//! without the app: always-on, or pre-logon (only while nobody is signed in). The app never
//! connects them itself; it sends the service their settings whenever they change, and the
//! service stores them where only it can read them and reconciles running tunnels against them.
//!
//! Only locations without MFA and without posture policies qualify: both need a signed-in user.
//! The polling token is not sent: the service never talks to XGuard itself.

use std::{
    collections::HashMap,
    hash::{DefaultHasher, Hash, Hasher},
    sync::{LazyLock, Mutex},
};

use prost::Message;
use xguard_client_proto::xguard::client::v1::{
    SaveServiceLocationsRequest, ServiceLocation, ServiceLocationMode as DaemonMode,
};

use crate::database::models::{
    Id,
    instance::{ClientTrafficPolicy, Instance},
    location::{Location, LocationMfaMode, ServiceLocationMode},
    wireguard_keys::WireguardKeys,
};
#[cfg(not(target_os = "macos"))]
use crate::{database::DbPool, error::Error};

/// Whether the background service should run `location`.
#[must_use]
pub fn is_daemon_service_location<I>(location: &Location<I>) -> bool {
    location.service_location_mode != ServiceLocationMode::Disabled
        && location.location_mfa_mode == LocationMfaMode::Disabled
        && !location.posture_check_required
}

/// The service locations of an instance, in a stable order.
#[must_use]
pub fn daemon_service_locations(
    locations: &[Location<Id>],
    traffic_policy: &ClientTrafficPolicy,
) -> Vec<ServiceLocation> {
    let forced_all = *traffic_policy == ClientTrafficPolicy::ForceAllTraffic;
    let mut service: Vec<ServiceLocation> = locations
        .iter()
        .filter(|location| is_daemon_service_location(location))
        .map(|location| ServiceLocation {
            name: location.name.clone(),
            address: location.address.clone(),
            pubkey: location.pubkey.clone(),
            endpoint: location.endpoint.clone(),
            allowed_ips: if forced_all {
                format!(
                    "{}, {}",
                    crate::DEFAULT_ROUTE_IPV4,
                    crate::DEFAULT_ROUTE_IPV6
                )
            } else {
                location.allowed_ips.clone()
            },
            keepalive_interval: u32::try_from(location.keepalive_interval.clamp(0, 3600))
                .unwrap_or(25),
            dns: location.dns.clone().unwrap_or_default(),
            mode: match location.service_location_mode {
                ServiceLocationMode::PreLogon => DaemonMode::PreLogon,
                _ => DaemonMode::AlwaysOn,
            } as i32,
            core_location_id: location.network_id,
            posture_check_required: false,
            mtu: location.client_mtu,
        })
        .collect();
    service.sort_by_key(|location| location.core_location_id);
    service
}

/// The request saving `service` for `instance`.
#[must_use]
pub fn save_request(
    instance: &Instance<Id>,
    keys: &WireguardKeys<Id>,
    service: Vec<ServiceLocation>,
) -> SaveServiceLocationsRequest {
    SaveServiceLocationsRequest {
        service_locations: service,
        instance_id: instance.uuid.clone(),
        private_key: keys.prvkey.clone(),
        proxy_url: instance.proxy_url.clone(),
        device_pubkey: keys.pubkey.clone(),
        token: None,
    }
}

/// What was last handed to the service per instance UUID: a digest of the request, or `None`
/// after a delete. Saves are skipped when nothing changed.
static LAST_PUSHED: LazyLock<Mutex<HashMap<String, Option<u64>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn last_pushed() -> std::sync::MutexGuard<'static, HashMap<String, Option<u64>>> {
    LAST_PUSHED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn digest(request: &SaveServiceLocationsRequest) -> u64 {
    let mut hasher = DefaultHasher::new();
    request.encode_to_vec().hash(&mut hasher);
    hasher.finish()
}

/// Sends the instance's service locations to the background service when they changed since the
/// last push (or removes them when there are none any more). Returns whether the service was
/// called.
#[cfg(not(target_os = "macos"))]
pub async fn sync_service_locations(pool: &DbPool, instance: &Instance<Id>) -> Result<bool, Error> {
    use xguard_client_proto::xguard::client::v1::DeleteServiceLocationsRequest;

    use crate::connection::daemon_client::DAEMON_CLIENT;

    let locations = Location::find_by_instance_id(pool, instance.id, true).await?;
    let service = daemon_service_locations(&locations, &instance.client_traffic_policy);
    if service.is_empty() {
        if last_pushed().get(&instance.uuid) == Some(&None) {
            return Ok(false);
        }
        DAEMON_CLIENT
            .clone()
            .delete_service_locations(DeleteServiceLocationsRequest {
                instance_id: instance.uuid.clone(),
            })
            .await
            .map_err(|status| Error::ServiceUnavailable(status.message().to_string()))?;
        last_pushed().insert(instance.uuid.clone(), None);
        return Ok(true);
    }

    let keys = WireguardKeys::find_by_instance_id(pool, instance.id)
        .await?
        .ok_or_else(|| Error::InternalError(format!("no keys for instance {instance}")))?;
    let request = save_request(instance, &keys, service);
    let digest = digest(&request);
    if last_pushed().get(&instance.uuid) == Some(&Some(digest)) {
        return Ok(false);
    }
    let count = request.service_locations.len();
    if let Err(status) = DAEMON_CLIENT.clone().save_service_locations(request).await {
        last_pushed().remove(&instance.uuid);
        return Err(Error::ServiceUnavailable(status.message().to_string()));
    }
    info!("Handed {count} service location(s) of instance {instance} to the background service");
    last_pushed().insert(instance.uuid.clone(), Some(digest));
    Ok(true)
}

/// Service locations are not available on macOS.
#[cfg(target_os = "macos")]
pub async fn sync_service_locations(
    _pool: &crate::database::DbPool,
    _instance: &Instance<Id>,
) -> Result<bool, crate::error::Error> {
    Ok(false)
}

/// Removes the instance's service locations from the background service (instance deleted).
#[cfg(not(target_os = "macos"))]
pub async fn remove_service_locations(instance_uuid: &str) -> Result<(), Error> {
    use xguard_client_proto::xguard::client::v1::DeleteServiceLocationsRequest;

    use crate::connection::daemon_client::DAEMON_CLIENT;

    DAEMON_CLIENT
        .clone()
        .delete_service_locations(DeleteServiceLocationsRequest {
            instance_id: instance_uuid.to_owned(),
        })
        .await
        .map_err(|status| Error::ServiceUnavailable(status.message().to_string()))?;
    last_pushed().remove(instance_uuid);
    Ok(())
}

#[cfg(target_os = "macos")]
pub async fn remove_service_locations(_instance_uuid: &str) -> Result<(), crate::error::Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use sqlx::types::Json;

    use super::*;

    fn location(network_id: Id, mode: ServiceLocationMode, mfa: LocationMfaMode) -> Location<Id> {
        Location {
            id: network_id,
            instance_id: 1,
            network_id,
            name: format!("n{network_id}"),
            address: "10.0.0.2/24".into(),
            pubkey: "pk".into(),
            endpoint: "vpn.example.com:51820".into(),
            allowed_ips: "10.0.0.0/24".into(),
            dns: Some("10.0.0.53".into()),
            route_all_traffic: false,
            keepalive_interval: 25,
            location_mfa_mode: mfa,
            service_location_mode: mode,
            mfa_method: None,
            posture_check_required: false,
            mfa_steps: Json::default(),
            mfa_step_plan: Json::default(),
            client_mtu: Some(1380),
        }
    }

    #[test]
    fn only_plain_service_locations_go_to_the_service() {
        let mut posture = location(5, ServiceLocationMode::AlwaysOn, LocationMfaMode::Disabled);
        posture.posture_check_required = true;
        let locations = vec![
            location(4, ServiceLocationMode::AlwaysOn, LocationMfaMode::Disabled),
            location(1, ServiceLocationMode::PreLogon, LocationMfaMode::Disabled),
            location(2, ServiceLocationMode::Disabled, LocationMfaMode::Disabled),
            location(3, ServiceLocationMode::AlwaysOn, LocationMfaMode::Internal),
            posture,
        ];
        let service = daemon_service_locations(&locations, &ClientTrafficPolicy::None);
        let ids: Vec<_> = service.iter().map(|l| l.core_location_id).collect();
        assert_eq!(ids, [1, 4]);
        assert_eq!(service[0].mode, DaemonMode::PreLogon as i32);
        assert_eq!(service[1].mode, DaemonMode::AlwaysOn as i32);
        assert_eq!(service[1].mtu, Some(1380));
        assert_eq!(service[1].dns, "10.0.0.53");
    }

    #[test]
    fn force_all_traffic_overrides_allowed_ips() {
        let locations = vec![location(
            1,
            ServiceLocationMode::AlwaysOn,
            LocationMfaMode::Disabled,
        )];
        let forced = daemon_service_locations(&locations, &ClientTrafficPolicy::ForceAllTraffic);
        assert_eq!(forced[0].allowed_ips, "0.0.0.0/0, ::/0");

        let normal = daemon_service_locations(&locations, &ClientTrafficPolicy::None);
        assert_eq!(normal[0].allowed_ips, "10.0.0.0/24");
    }

    #[sqlx::test(migrations = "../migrations")]
    async fn request_carries_no_polling_token_and_digest_tracks_changes(pool: sqlx::SqlitePool) {
        let mut instance = Instance::from(crate::proto::client_types::InstanceInfo {
            id: "2b9a4b8e-8b8e-4d4e-9a3f-1c2d3e4f5a6b".into(),
            name: "office".into(),
            proxy_url: "https://edge".into(),
            ..Default::default()
        });
        instance.token = Some("secret-token".into());
        let instance = instance.save(&pool).await.unwrap();
        let keys = WireguardKeys {
            id: 1,
            instance_id: 1,
            pubkey: "device-pub".into(),
            prvkey: "device-prv".into(),
        };
        let service = daemon_service_locations(
            &[location(
                1,
                ServiceLocationMode::AlwaysOn,
                LocationMfaMode::Disabled,
            )],
            &ClientTrafficPolicy::None,
        );
        let request = save_request(&instance, &keys, service.clone());
        assert!(request.token.is_none());
        assert_eq!(request.instance_id, instance.uuid);
        let mut other = save_request(&instance, &keys, service);
        assert_eq!(digest(&request), digest(&other));
        other.service_locations[0].endpoint = "other:51820".into();
        assert_ne!(digest(&request), digest(&other));
    }
}
