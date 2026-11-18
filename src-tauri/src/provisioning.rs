//! Finds a provisioning file at start-up (only while no instance is enrolled) so the UI can
//! start the enrollment with it. Parsing and permission checks live in
//! `xguard_client_core::provisioning`.

use chrono::Utc;
use tauri::{AppHandle, Manager};
use xguard_client_core::{
    database::{models::instance::Instance, DB_POOL},
    provisioning::{find_provisioning, FoundProvisioning},
};

pub async fn handle_client_initialization(app_handle: &AppHandle) -> Option<FoundProvisioning> {
    match Instance::all(&*DB_POOL).await {
        Ok(instances) if instances.is_empty() => {
            let data_dir = app_handle.path().app_data_dir().ok()?;
            find_provisioning(&data_dir, Utc::now())
        }
        Ok(_) => None,
        Err(err) => {
            error!("Failed to check whether the client is enrolled: {err}");
            None
        }
    }
}
