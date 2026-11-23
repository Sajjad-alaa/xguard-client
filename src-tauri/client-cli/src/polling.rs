//! One configuration sync pass when the CLI starts, so commands see the current configuration.
//! Bounded in time; failures never stop the command.

use std::{collections::HashSet, time::Duration};

use tracing::{debug, warn};
use xguard_core::{
    ConnectionType,
    config_sync::{PollError, SyncError, TunnelAction, sync_instance},
    connection::{active_state::active_state, tear_down},
    database::models::instance::Instance,
    service_locations::sync_service_locations,
};

use crate::state::State;

/// Upper bound on the whole pass.
const SYNC_BUDGET: Duration = Duration::from_secs(8);

pub async fn poll_config(state: &State) {
    if tokio::time::timeout(SYNC_BUDGET, sync_all(state))
        .await
        .is_err()
    {
        debug!("Configuration sync did not finish in time; continuing");
    }
}

async fn sync_all(state: &State) {
    let active_connections = match active_state(&state.pool).await {
        Ok(connections) => connections,
        Err(err) => {
            debug!("Skipping configuration sync, failed to detect active connections: {err}");
            return;
        }
    };
    let active: HashSet<_> = active_connections
        .iter()
        .filter(|connection| connection.connection_type == ConnectionType::Location)
        .map(|connection| connection.target_id)
        .collect();
    let instances = match Instance::all_with_token(&state.pool).await {
        Ok(instances) => instances,
        Err(err) => {
            debug!("Skipping configuration sync: {err}");
            return;
        }
    };
    for instance in instances {
        match sync_instance(&state.pool, instance.id, &active).await {
            Ok(report) => {
                for action in &report.actions {
                    if let TunnelAction::Disconnect(id) | TunnelAction::DisconnectForPolicy(id) =
                        action
                    {
                        if let Some(conn) = active_connections.iter().find(|c| {
                            c.connection_type == ConnectionType::Location && c.target_id == *id
                        }) {
                            if let Err(err) = tear_down(conn).await {
                                warn!(
                                    "Failed to disconnect location {} during configuration sync: {err}",
                                    conn.name
                                );
                            }
                        }
                    }
                }
                if report.actions.iter().any(|action| {
                    matches!(
                        action,
                        TunnelAction::Reconnect(_)
                            | TunnelAction::ReconnectByUser(_)
                            | TunnelAction::Disconnect(_)
                            | TunnelAction::DisconnectForPolicy(_)
                    )
                }) {
                    eprintln!(
                        "Instance {} configuration changed, reconnect to apply the changes",
                        report.instance_name
                    );
                }
                let target = Instance::find_by_id(&state.pool, instance.id)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or(instance);
                if let Err(err) = sync_service_locations(&state.pool, &target).await {
                    debug!("Failed to hand service locations to the background service: {err}");
                }
            }
            Err(SyncError::Poll(PollError::Unsupported) | SyncError::NoToken) => {}
            Err(err) => debug!(
                "Configuration sync of instance {} failed: {err}",
                instance.name
            ),
        }
    }
}
