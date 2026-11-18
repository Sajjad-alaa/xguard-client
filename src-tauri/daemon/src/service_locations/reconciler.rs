//! Desired versus actual service-location tunnels. Pure, so the decisions are easy to test.

use std::{
    collections::{BTreeMap, HashMap},
    hash::{DefaultHasher, Hash, Hasher},
};

use super::store::{Mode, StoredInstance, StoredLocation};

/// Identifies one service-location tunnel.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TunnelKey {
    pub instance_id: String,
    pub network_id: i64,
}

/// A tunnel the stored configuration asks for.
#[derive(Clone, Debug)]
pub struct DesiredTunnel {
    pub key: TunnelKey,
    pub mode: Mode,
    /// Changes whenever anything that shapes the tunnel changes (keys included).
    pub fingerprint: u64,
    pub private_key: String,
    pub location: StoredLocation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Up(TunnelKey),
    Down(TunnelKey),
    /// Settings changed: take the tunnel down and bring it up again.
    Replace(TunnelKey),
}

/// Interface name for a service-location tunnel: `xgs` and 8 hex digits, stable per tunnel and
/// within the 15-character Linux limit. The prefix keeps it apart from the app's `wg*` tunnels.
#[must_use]
pub fn interface_name(key: &TunnelKey) -> String {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    #[allow(clippy::cast_possible_truncation)]
    let short = hasher.finish() as u32;
    format!("xgs{short:08x}")
}

#[must_use]
pub fn desired_tunnels(instances: &[StoredInstance]) -> Vec<DesiredTunnel> {
    let mut desired = Vec::new();
    for instance in instances {
        for location in &instance.locations {
            let mut hasher = DefaultHasher::new();
            instance.private_key.hash(&mut hasher);
            location.hash(&mut hasher);
            desired.push(DesiredTunnel {
                key: TunnelKey {
                    instance_id: instance.instance_id.clone(),
                    network_id: location.network_id,
                },
                mode: location.mode,
                fingerprint: hasher.finish(),
                private_key: instance.private_key.clone(),
                location: location.clone(),
            });
        }
    }
    desired
}

/// Whether a tunnel in `mode` should run now.
#[must_use]
pub fn wanted(mode: Mode, user_signed_in: bool) -> bool {
    match mode {
        Mode::AlwaysOn => true,
        Mode::PreLogon => !user_signed_in,
    }
}

/// What to do to bring `running` (tunnel -> fingerprint it was built from) in line with
/// `desired`. Already-correct tunnels are left alone. Downs come before ups, so a replaced
/// route is free before its successor needs it; the order is otherwise deterministic.
#[must_use]
pub fn plan(
    desired: &[DesiredTunnel],
    running: &HashMap<TunnelKey, u64>,
    user_signed_in: bool,
) -> Vec<Action> {
    let wanted_now: BTreeMap<&TunnelKey, u64> = desired
        .iter()
        .filter(|tunnel| wanted(tunnel.mode, user_signed_in))
        .map(|tunnel| (&tunnel.key, tunnel.fingerprint))
        .collect();
    let mut downs: Vec<TunnelKey> = running
        .keys()
        .filter(|key| !wanted_now.contains_key(key))
        .cloned()
        .collect();
    downs.sort();
    let mut actions: Vec<Action> = downs.into_iter().map(Action::Down).collect();
    for (key, fingerprint) in wanted_now {
        match running.get(key) {
            None => actions.push(Action::Up(key.clone())),
            Some(current) if *current != fingerprint => actions.push(Action::Replace(key.clone())),
            Some(_) => {}
        }
    }
    actions
}
