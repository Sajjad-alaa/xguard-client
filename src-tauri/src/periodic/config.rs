//! Background configuration sync for every enrolled instance.
//!
//! Polls each instance through Edge on its own schedule (server-suggested interval, backoff on
//! errors, jitter), right after start-up, when the network changes and when asked to
//! ([`request_config_sync`]: manual refresh, after a disconnect, after an MFA change). Changes
//! are applied with `instance_sync`; live tunnels are disconnected, reconnected or the user is
//! asked to reconnect, and service locations are handed to the background service.

use std::{
    collections::{HashMap, HashSet},
    sync::LazyLock,
    time::{Duration, Instant},
};

use tauri::{AppHandle, Emitter};
use tokio::{sync::Notify, time::sleep};
use xguard_client_core::{
    ConnectionType,
    config_sync::{
        Attempt, PollError, SyncError, SyncSchedule, TunnelAction, jitter_unit,
        network_fingerprint, plan_tunnel_actions, sync_instance,
    },
    connection::active_connections::ACTIVE_CONNECTIONS,
    database::{
        DB_POOL,
        models::{Id, instance::Instance},
    },
    events::EventKey,
    service_locations::sync_service_locations,
};

use crate::{
    commands::{connect, disconnect, disconnect_all_tunnels},
    events::TunnelsEnabledPayload,
    tray::reload_tray_menu,
};

/// Wakes the sync loop.
static TRIGGER: LazyLock<Notify> = LazyLock::new(Notify::new);
/// How often the network is checked for changes.
const NETWORK_CHECK_INTERVAL: Duration = Duration::from_secs(10);
/// A triggered poll of an instance waits at least this long after its previous poll.
const MIN_TRIGGERED_GAP: Duration = Duration::from_secs(10);
/// Upper bound on one wait, so newly enrolled instances are picked up.
const MAX_WAIT: Duration = Duration::from_secs(60);

/// Asks the sync loop to poll every instance now (subject to [`MIN_TRIGGERED_GAP`]).
pub fn request_config_sync() {
    TRIGGER.notify_one();
}

struct InstanceState {
    schedule: SyncSchedule,
    next: Instant,
    last: Option<Instant>,
}

pub(crate) async fn active_location_ids() -> HashSet<Id> {
    ACTIVE_CONNECTIONS
        .lock()
        .await
        .iter()
        .filter(|connection| connection.connection_type == ConnectionType::Location)
        .map(|connection| connection.location_id)
        .collect()
}

pub(crate) async fn apply_actions(
    handle: &AppHandle,
    instance_name: &str,
    actions: Vec<TunnelAction>,
) {
    let mut ask_user = false;
    for action in actions {
        match action {
            TunnelAction::Disconnect(id) => {
                info!(
                    "Location {id} was removed or is now run by the background service; disconnecting"
                );
                if let Err(err) = disconnect(id, ConnectionType::Location, handle.clone()).await {
                    warn!("Failed to disconnect location {id}: {err}");
                }
            }
            TunnelAction::DisconnectForPolicy(id) => {
                info!("Policy tightened for active MFA location {id}; disconnecting");
                if let Err(err) = disconnect(id, ConnectionType::Location, handle.clone()).await {
                    warn!("Failed to disconnect location {id} for policy change: {err}");
                }
                ask_user = true;
            }
            TunnelAction::Reconnect(id) => {
                info!("Location {id} settings changed; reconnecting");
                if let Err(err) = disconnect(id, ConnectionType::Location, handle.clone()).await {
                    warn!("Failed to disconnect location {id} for a reconnect: {err}");
                    continue;
                }
                if let Err(err) = connect(id, ConnectionType::Location, handle.clone()).await {
                    warn!("Failed to reconnect location {id}: {err:?}");
                    ask_user = true;
                }
            }
            TunnelAction::ReconnectByUser(_) => ask_user = true,
        }
    }
    if ask_user {
        // The UI asks the user to reconnect (MFA locations cannot reconnect on their own).
        if let Err(err) = handle.emit(EventKey::ConfigChanged.into(), instance_name) {
            error!("Failed to emit config-changed event: {err}");
        }
    }
}

/// Polls one instance and applies the result. Returns the attempt for scheduling.
async fn sync_one(handle: &AppHandle, instance_id: Id) -> Attempt {
    let active = active_location_ids().await;
    let tunnels_were_disabled = Instance::tunnels_disabled(&*DB_POOL).await.unwrap_or(false);
    let report = match sync_instance(&DB_POOL, instance_id, &active).await {
        Ok(report) => report,
        Err(SyncError::Poll(err)) => {
            match &err {
                PollError::Unsupported => {
                    debug!("Instance {instance_id} does not serve configuration polling");
                }
                PollError::Unauthorized | PollError::Forbidden => warn!(
                    "Instance {instance_id} refused configuration sync ({err}); the device may \
                    have been removed or the user disabled"
                ),
                _ => debug!("Configuration sync of instance {instance_id} failed: {err}"),
            }
            return Attempt::from_result::<()>(&Err(err), None);
        }
        Err(SyncError::NoToken | SyncError::NotFound(_)) => return Attempt::Rejected,
        Err(SyncError::Local(err)) => {
            error!("Failed to apply the configuration of instance {instance_id}: {err}");
            return Attempt::Failed;
        }
    };

    if report.changed() {
        info!(
            "Applied the new configuration of instance {}: {:?}",
            report.instance_name, report.summary
        );
        if let Err(err) = handle.emit(EventKey::InstanceUpdated.into(), ()) {
            error!("Failed to emit instance-updated event: {err}");
        }
        if let Err(err) = handle.emit(EventKey::InstanceUpdate.into(), ()) {
            error!("Failed to emit instance-update event: {err}");
        }
        reload_tray_menu(handle).await;

        let tunnels_disabled = Instance::tunnels_disabled(&*DB_POOL).await.unwrap_or(false);
        if tunnels_disabled && !tunnels_were_disabled {
            info!("Tunnels disabled by the administrator, disconnecting tunnels");
            if let Err(err) = disconnect_all_tunnels(handle).await {
                error!("Failed to disconnect tunnels: {err}");
            }
        } else if !tunnels_disabled && tunnels_were_disabled {
            TunnelsEnabledPayload::emit(handle);
        }
    }
    let interval = report.interval;
    let name = report.instance_name.clone();
    if let Some(summary) = &report.summary {
        let fresh_active = active_location_ids().await;
        let actions = plan_tunnel_actions(summary, &fresh_active, &report.after_locations);
        apply_actions(handle, &name, actions).await;
    } else {
        apply_actions(handle, &name, report.actions).await;
    }

    // Cheap when nothing changed (compared with what was last handed over).
    if let Ok(Some(instance)) = Instance::find_by_id(&*DB_POOL, instance_id).await {
        if let Err(err) = sync_service_locations(&DB_POOL, &instance).await {
            warn!(
                "Failed to hand service locations of {instance} to the background service: {err}"
            );
        }
    }
    Attempt::Succeeded(interval)
}

/// Runs forever, polling every instance that has a polling token.
pub async fn poll_config(handle: AppHandle) {
    debug!("Starting configuration sync");
    // Give the frontend a moment to subscribe to events, and spread clients started together.
    sleep(Duration::from_secs(2) + Duration::from_secs(3).mul_f64(jitter_unit())).await;

    let mut states: HashMap<Id, InstanceState> = HashMap::new();
    let mut fingerprint = network_fingerprint();
    let mut triggered = true;
    let mut network_check = tokio::time::interval(NETWORK_CHECK_INTERVAL);
    network_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let instances = match Instance::all_with_token(&*DB_POOL).await {
            Ok(instances) => instances,
            Err(err) => {
                error!("Failed to list instances for configuration sync: {err}");
                Vec::new()
            }
        };
        let ids: HashSet<Id> = instances.iter().map(|instance| instance.id).collect();
        states.retain(|id, _| ids.contains(id));

        let now = Instant::now();
        for instance in &instances {
            let state = states.entry(instance.id).or_insert_with(|| InstanceState {
                schedule: SyncSchedule::default(),
                next: now,
                last: None,
            });
            let due = state.next <= now
                || (triggered
                    && state
                        .last
                        .is_none_or(|last| now.duration_since(last) >= MIN_TRIGGERED_GAP));
            if !due {
                continue;
            }
            let attempt = sync_one(&handle, instance.id).await;
            let finished = Instant::now();
            state.last = Some(finished);
            state.next = finished + state.schedule.next_delay(attempt, jitter_unit());
        }
        triggered = false;

        let wait = states
            .values()
            .map(|state| state.next.saturating_duration_since(Instant::now()))
            .min()
            .unwrap_or(MAX_WAIT)
            .clamp(Duration::from_secs(1), MAX_WAIT);
        let deadline = tokio::time::sleep(wait);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                () = &mut deadline => break,
                () = TRIGGER.notified() => {
                    triggered = true;
                    break;
                }
                _ = network_check.tick() => {
                    let current = network_fingerprint();
                    if current != fingerprint {
                        debug!("Network changed, syncing configuration");
                        fingerprint = current;
                        triggered = true;
                        break;
                    }
                }
            }
        }
    }
}
