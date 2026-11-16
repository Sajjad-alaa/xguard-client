//! Applying a device configuration received from XGuard to the local database.
//!
//! The server owns the instance description and the location network settings; the user owns
//! local preferences such as "route all traffic" and the chosen MFA method. Updates replace the
//! former and keep the latter, so refreshing an instance never resets what the user picked.

use std::collections::HashMap;

use sqlx::SqliteConnection;

use crate::{
    database::models::{
        instance::Instance,
        location::{infer_mfa_method, Location},
        Id,
    },
    error::Error,
    into_location,
    proto::client_types::DeviceConfigResponse,
};

/// What [`apply_device_config`] changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SyncSummary {
    pub instance_changed: bool,
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
}

impl SyncSummary {
    /// Whether the set of locations or any location's settings changed.
    #[must_use]
    pub fn locations_changed(&self) -> bool {
        self.added + self.updated + self.removed > 0
    }
}

/// Brings `instance` and its locations in line with `response`.
///
/// Locations are matched on the server's network ID: matching ones are updated in place (keeping
/// their local ID, statistics and user preferences), new ones are inserted and ones the server no
/// longer sends are deleted. Rows that did not change are not written. Runs on a single connection
/// so the caller can wrap it in a transaction and apply all of it or none of it.
pub async fn apply_device_config(
    conn: &mut SqliteConnection,
    instance: &mut Instance<Id>,
    response: DeviceConfigResponse,
) -> Result<SyncSummary, Error> {
    let info = response.instance.ok_or_else(|| {
        Error::ResourceNotFound("instance info in device config response".to_string())
    })?;
    if info.id != instance.uuid {
        // Never let one server's answer overwrite another instance.
        return Err(Error::InvalidInput(format!(
            "device config belongs to instance {}, not {}",
            info.id, instance.uuid
        )));
    }

    let mut summary = SyncSummary {
        instance_changed: update_instance(instance, info, response.token),
        ..SyncSummary::default()
    };
    if summary.instance_changed {
        instance.save(&mut *conn).await?;
    }

    let mut existing: HashMap<Id, Location<Id>> =
        Location::find_by_instance_id(&mut *conn, instance.id, true)
            .await?
            .into_iter()
            .map(|location| (location.network_id, location))
            .collect();

    for config in response.configs {
        let incoming = into_location(config, instance.id);
        match existing.remove(&incoming.network_id) {
            Some(mut current) => {
                if merge_location(&mut current, incoming) {
                    current.save(&mut *conn).await?;
                    summary.updated += 1;
                }
            }
            None => {
                incoming.save(&mut *conn).await?;
                summary.added += 1;
            }
        }
    }

    for stale in existing.into_values() {
        debug!("Removing location {stale}, it is no longer assigned to this device");
        stale.delete(&mut *conn).await?;
        summary.removed += 1;
    }

    Ok(summary)
}

/// Copies server-owned instance fields from `info`. Returns whether anything changed.
fn update_instance(
    instance: &mut Instance<Id>,
    info: crate::proto::client_types::InstanceInfo,
    token: Option<String>,
) -> bool {
    let mut changed = instance.sync_mfa_state(&info);
    let fresh = Instance::from(info);

    macro_rules! take {
        ($($field:ident),+) => {$(
            if instance.$field != fresh.$field {
                instance.$field = fresh.$field;
                changed = true;
            }
        )+};
    }
    take!(
        name,
        url,
        proxy_url,
        username,
        client_traffic_policy,
        enterprise_enabled,
        disable_tunnels,
        openid_display_name,
        openid_provider_kind,
        mfa_contract
    );

    // An absent token means "unchanged", not "revoked": older servers omit it on refresh.
    if token.is_some() && instance.token != token {
        instance.token = token;
        changed = true;
    }
    changed
}

/// Replaces the server-owned fields of `current` with those of `incoming`, keeping the user's
/// local preferences. Returns whether anything changed.
fn merge_location(current: &mut Location<Id>, incoming: Location) -> bool {
    let steps_changed = current.mfa_steps != incoming.mfa_steps;
    let mut updated = Location {
        id: current.id,
        instance_id: current.instance_id,
        network_id: current.network_id,
        route_all_traffic: current.route_all_traffic,
        mfa_method: infer_mfa_method(incoming.location_mfa_mode, current.mfa_method),
        // A saved step plan only makes sense for the steps it was made for.
        mfa_step_plan: if steps_changed {
            sqlx::types::Json::default()
        } else {
            current.mfa_step_plan.clone()
        },
        name: incoming.name,
        address: incoming.address,
        pubkey: incoming.pubkey,
        endpoint: incoming.endpoint,
        allowed_ips: incoming.allowed_ips,
        dns: incoming.dns,
        keepalive_interval: incoming.keepalive_interval,
        location_mfa_mode: incoming.location_mfa_mode,
        service_location_mode: incoming.service_location_mode,
        posture_check_required: incoming.posture_check_required,
        mfa_steps: incoming.mfa_steps,
        client_mtu: incoming.client_mtu,
    };
    if updated == *current {
        return false;
    }
    std::mem::swap(current, &mut updated);
    true
}

#[cfg(test)]
mod tests;
