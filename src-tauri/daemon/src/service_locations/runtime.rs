//! Running service-location tunnels (Linux and Windows).

use std::{collections::HashMap, str::FromStr, sync::Arc, time::Duration};

use tokio::sync::{Mutex, Notify};
use tracing::{debug, error, info, warn};
use xguard_wireguard_rs::{
    InterfaceConfiguration, WireguardInterfaceApi, key::Key, net::IpAddrMask, peer::Peer,
};

use super::{
    reconciler::{Action, DesiredTunnel, TunnelKey, desired_tunnels, interface_name, plan},
    session::user_signed_in,
    store::{Store, StoredInstance},
};
use crate::daemon::{WG, configure_interface, setup_wgapi};

/// How often the reconciler runs without being woken. It also retries tunnels whose endpoint
/// did not resolve yet (for example before the network is up at boot).
pub(crate) const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

struct Running {
    ifname: String,
    fingerprint: u64,
    endpoint: String,
    wgapi: WG,
}

pub(crate) struct ServiceLocationManager {
    store: Store,
    running: HashMap<TunnelKey, Running>,
}

fn interface_configuration(
    tunnel: &DesiredTunnel,
    ifname: &str,
) -> Result<InterfaceConfiguration, String> {
    let location = &tunnel.location;
    let mut peer = Peer::new(Key::from_str(&location.pubkey).map_err(|err| err.to_string())?);
    peer.set_endpoint(&location.endpoint)
        .map_err(|err| format!("endpoint {}: {err}", location.endpoint))?;
    peer.persistent_keepalive_interval =
        (location.keepalive_interval > 0).then_some(location.keepalive_interval);
    peer.allowed_ips = location
        .allowed_ips
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(IpAddrMask::from_str)
        .collect::<Result<_, _>>()
        .map_err(|err| err.to_string())?;
    let addresses = location
        .address
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(IpAddrMask::from_str)
        .collect::<Result<_, _>>()
        .map_err(|err| err.to_string())?;
    Ok(InterfaceConfiguration {
        name: ifname.to_owned(),
        prvkey: tunnel.private_key.clone(),
        addresses,
        port: 0,
        peers: vec![peer],
        mtu: location.mtu,
        fwmark: None,
    })
}

impl ServiceLocationManager {
    pub(crate) fn new(store: Store) -> Self {
        Self {
            store,
            running: HashMap::new(),
        }
    }

    pub(crate) fn store(&self) -> &Store {
        &self.store
    }

    /// Validates and stores the app's request. Returns whether anything changed.
    pub(crate) fn save(&self, instance: &StoredInstance) -> Result<bool, super::store::StoreError> {
        self.store.save(instance)
    }

    fn bring_up(&mut self, tunnel: &DesiredTunnel) -> Result<(), String> {
        let ifname = interface_name(&tunnel.key);
        let mut config = interface_configuration(tunnel, &ifname)?;
        let mut wgapi = setup_wgapi(&ifname).map_err(|status| status.message().to_owned())?;
        // A tunnel left behind by a crashed service would make creation fail.
        let _ = wgapi.remove_interface();
        wgapi
            .create_interface()
            .map_err(|err| format!("create {ifname}: {err}"))?;
        let dns = tunnel.location.dns.clone();
        if let Err(status) = configure_interface(&ifname, &dns, &mut wgapi, &mut config) {
            #[cfg(not(windows))]
            let _ = wgapi.remove_endpoint_routing(&tunnel.location.endpoint);
            let _ = wgapi.remove_interface();
            return Err(status.message().to_owned());
        }
        info!("Service location {} ({ifname}) is up", tunnel.location.name);
        self.running.insert(
            tunnel.key.clone(),
            Running {
                ifname,
                fingerprint: tunnel.fingerprint,
                endpoint: tunnel.location.endpoint.clone(),
                wgapi,
            },
        );
        Ok(())
    }

    fn take_down(&mut self, key: &TunnelKey) {
        let Some(running) = self.running.remove(key) else {
            return;
        };
        #[allow(unused_mut)]
        let mut wgapi = running.wgapi;
        #[cfg(not(windows))]
        if let Err(err) = wgapi.remove_endpoint_routing(&running.endpoint) {
            debug!("Failed to remove routing for {}: {err}", running.endpoint);
        }
        #[cfg(windows)]
        let _ = &running.endpoint;
        match wgapi.remove_interface() {
            Ok(()) => info!("Service location tunnel {} is down", running.ifname),
            Err(err) => error!(
                "Failed to remove service location tunnel {}: {err}",
                running.ifname
            ),
        }
    }

    /// Drops tunnels whose interface disappeared (removed by hand, driver reset), so the next
    /// plan brings them back.
    fn forget_dead_tunnels(&mut self) {
        let dead: Vec<TunnelKey> = self
            .running
            .iter()
            .filter(|(_, running)| running.wgapi.read_interface_data().is_err())
            .map(|(key, _)| key.clone())
            .collect();
        for key in dead {
            warn!("Service location tunnel for {key:?} disappeared; it will be recreated");
            self.take_down(&key);
        }
    }

    /// One reconciliation pass.
    pub(crate) fn reconcile(&mut self, user_signed_in: bool) {
        self.forget_dead_tunnels();
        let desired = desired_tunnels(&self.store.load_all());
        let running: HashMap<TunnelKey, u64> = self
            .running
            .iter()
            .map(|(key, running)| (key.clone(), running.fingerprint))
            .collect();
        let by_key: HashMap<&TunnelKey, &DesiredTunnel> =
            desired.iter().map(|tunnel| (&tunnel.key, tunnel)).collect();
        for action in plan(&desired, &running, user_signed_in) {
            match action {
                Action::Down(key) => self.take_down(&key),
                Action::Up(key) | Action::Replace(key) => {
                    self.take_down(&key);
                    if let Some(tunnel) = by_key.get(&key) {
                        if let Err(err) = self.bring_up(tunnel) {
                            // Retried on the next pass (e.g. DNS not available yet).
                            warn!(
                                "Service location {} not up yet: {err}",
                                tunnel.location.name
                            );
                        }
                    }
                }
            }
        }
    }

    /// Removes every tunnel (service shutdown).
    pub(crate) fn shut_down(&mut self) {
        let keys: Vec<TunnelKey> = self.running.keys().cloned().collect();
        for key in keys {
            self.take_down(&key);
        }
    }
}

/// Wakes the reconciler (app saved settings, resume, session change).
static WAKE: std::sync::LazyLock<Arc<Notify>> =
    std::sync::LazyLock::new(|| Arc::new(Notify::new()));

/// Asks the reconciler to run now.
pub(crate) fn wake_reconciler() {
    WAKE.notify_one();
}

/// Reconciles until the task is aborted: every [`RECONCILE_INTERVAL`] and whenever
/// [`wake_reconciler`] is called. Each pass runs on a blocking thread: bringing a tunnel up
/// resolves its endpoint and talks to the kernel.
pub(crate) async fn run_reconciler(manager: Arc<Mutex<ServiceLocationManager>>) {
    let wake = Arc::clone(&WAKE);
    loop {
        let pass = Arc::clone(&manager);
        if let Err(err) = tokio::task::spawn_blocking(move || {
            let signed_in = user_signed_in();
            pass.blocking_lock().reconcile(signed_in);
        })
        .await
        {
            error!("Service location reconciliation failed: {err}");
        }
        tokio::select! {
            () = tokio::time::sleep(RECONCILE_INTERVAL) => {}
            () = wake.notified() => debug!("Service location reconciler woken"),
        }
    }
}
