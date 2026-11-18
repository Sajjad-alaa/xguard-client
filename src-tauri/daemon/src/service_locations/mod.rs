//! Service locations: tunnels the background service keeps up without the app.
//!
//! The app hands the service an instance's service locations ([`store`]); the reconciler
//! compares what is stored (and, for pre-logon locations, whether a user is signed in) with the
//! tunnels it runs, and brings them in line: on a timer, when the app saves new settings, and
//! (on Windows) on resume and session changes.
//!
//! Privilege separation: the service runs privileged and the app does not. The app can only
//! reach the service over its local socket (group `xguard` on Linux) or named pipe, every
//! request is validated, stored files are readable only by the service account, and the service
//! never sends a stored private key back. The service never talks to XGuard itself.

pub mod reconciler;
pub mod session;
pub mod store;

#[cfg(any(windows, target_os = "linux"))]
mod runtime;

#[cfg(any(windows, target_os = "linux"))]
pub(crate) use runtime::{run_reconciler, wake_reconciler, ServiceLocationManager};

#[cfg(test)]
mod tests;
