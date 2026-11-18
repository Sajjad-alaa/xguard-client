//! One configuration sync pass when the CLI starts, so commands see the current configuration.
//! Bounded in time; failures never stop the command.

use std::{collections::HashSet, time::Duration};

use tracing::debug;
use xguard_core::{
    config_sync::{sync_instance, PollError, SyncError, TunnelAction},
    connection::active_state::active_state,
    database::models::instance::Instance,
    service_locations::sync_service_locations,
    ConnectionType,
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
    let active: HashSet<_> = match active_state(&state.pool).await {
        Ok(connections) => connections
            .into_iter()
            .filter(|connection| connection.connection_type == ConnectionType::Location)
            .map(|connection| connection.target_id)
            .collect(),
        Err(err) => {
            debug!("Skipping configuration sync, failed to detect active connections: {err}");
            return;
        }
    };
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
                if report.actions.iter().any(|action| {
                    matches!(
                        action,
                        TunnelAction::Reconnect(_)
                            | TunnelAction::ReconnectByUser(_)
                            | TunnelAction::Disconnect(_)
                    )
                }) {
                    eprintln!(
                        "Instance {} configuration changed, reconnect to apply the changes",
                        report.instance_name
                    );
                }
                if let Err(err) = sync_service_locations(&state.pool, &instance).await {
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
