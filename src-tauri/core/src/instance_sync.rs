//! Applying a device configuration received from XGuard to the local database.
//!
//! The server owns the instance description and the location network settings; the user owns
//! local preferences such as "route all traffic" and the chosen MFA method. Updates replace the
//! former and keep the latter, so refreshing an instance never resets what the user picked.

use std::collections::HashMap;

use sqlx::SqliteConnection;

use crate::{
    database::models::{
        Id,
        instance::Instance,
        location::{Location, LocationMfaMode, LocationMfaStep, infer_mfa_method, legacy_mfa_steps},
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
    /// Local IDs of the locations that were removed.
    pub removed_ids: Vec<Id>,
    /// Local IDs of updated locations whose tunnel settings changed (address, keys, endpoint,
    /// routes, DNS, MTU, keepalive, MFA or service mode): a live tunnel no longer matches them.
    /// Renames and other display-only changes are not listed.
    pub tunnel_changed_ids: Vec<Id>,
    /// Local IDs of updated locations whose MFA or posture requirements tightened.
    pub policy_tightened_ids: Vec<Id>,
    /// The client traffic policy changed, so the routing of every live tunnel may be stale.
    pub traffic_policy_changed: bool,
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

    let policy_before = instance.client_traffic_policy.clone();
    let mut summary = SyncSummary {
        instance_changed: update_instance(instance, info, response.token),
        ..SyncSummary::default()
    };
    summary.traffic_policy_changed = instance.client_traffic_policy != policy_before;
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
                let tunnel_changed = tunnel_settings_differ(&current, &incoming);
                let tightened = policy_tightened(&current, &incoming);
                if merge_location(&mut current, incoming) {
                    current.save(&mut *conn).await?;
                    summary.updated += 1;
                    if tunnel_changed {
                        summary.tunnel_changed_ids.push(current.id);
                    }
                    if tightened {
                        summary.policy_tightened_ids.push(current.id);
                    }
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
        summary.removed_ids.push(stale.id);
    }
    summary.removed_ids.sort_unstable();
    summary.tunnel_changed_ids.sort_unstable();
    summary.policy_tightened_ids.sort_unstable();

    Ok(summary)
}

fn effective_mfa_steps(
    mode: LocationMfaMode,
    steps: &[LocationMfaStep],
) -> Vec<LocationMfaStep> {
    if steps.is_empty() {
        legacy_mfa_steps(mode)
    } else {
        steps.to_vec()
    }
}

/// Whether `incoming` imposes stricter posture or MFA requirements than `current`.
fn policy_tightened(current: &Location<Id>, incoming: &Location) -> bool {
    if !current.posture_check_required && incoming.posture_check_required {
        return true;
    }
    if incoming.location_mfa_mode == LocationMfaMode::Disabled {
        return false;
    }
    if current.location_mfa_mode == LocationMfaMode::Disabled {
        return true;
    }

    let prev_steps = effective_mfa_steps(current.location_mfa_mode, &current.mfa_steps.0);
    let next_steps = effective_mfa_steps(incoming.location_mfa_mode, &incoming.mfa_steps.0);

    if next_steps.len() > prev_steps.len() {
        return true;
    }

    prev_steps
        .iter()
        .zip(next_steps.iter())
        .any(|(prev_step, next_step)| {
            prev_step.methods.iter().any(|prev_m| {
                !next_step
                    .methods
                    .iter()
                    .any(|next_m| next_m.method == prev_m.method)
            })
        })
}

/// Copies server-owned instance fields from `info`. Returns whether anything changed.
fn update_instance(
    instance: &mut Instance<Id>,
    info: crate::proto::client_types::InstanceInfo,
    token: Option<String>,
) -> bool {
    let mut changed = instance.sync_mfa_state(&info);
    let fresh = Instance::from(info);

    if instance.url != fresh.url || instance.proxy_url != fresh.proxy_url {
        warn!(
            "Ignoring server attempt to change URLs of instance {} (kept url={} proxy_url={})",
            instance.name, instance.url, instance.proxy_url
        );
    }

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

/// Whether a tunnel built from `current` would differ from one built from `incoming`.
fn tunnel_settings_differ(current: &Location<Id>, incoming: &Location) -> bool {
    current.address != incoming.address
        || current.pubkey != incoming.pubkey
        || current.endpoint != incoming.endpoint
        || current.allowed_ips != incoming.allowed_ips
        || current.dns != incoming.dns
        || current.keepalive_interval != incoming.keepalive_interval
        || current.client_mtu != incoming.client_mtu
        || current.location_mfa_mode != incoming.location_mfa_mode
        || current.mfa_steps != incoming.mfa_steps
        || current.service_location_mode != incoming.service_location_mode
        || current.posture_check_required != incoming.posture_check_required
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
