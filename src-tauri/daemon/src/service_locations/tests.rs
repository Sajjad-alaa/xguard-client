use std::collections::HashMap;

use xguard_client_proto::xguard::client::v1::{
    SaveServiceLocationsRequest, ServiceLocation, ServiceLocationMode as ProtoMode,
};

use super::{
    reconciler::{Action, TunnelKey, desired_tunnels, interface_name, plan, wanted},
    store::{Mode, Store, StoreError, StoredInstance, validate_endpoint, validate_instance_id},
};

const INSTANCE: &str = "2b9a4b8e-8b8e-4d4e-9a3f-1c2d3e4f5a6b";
const KEY_A: &str = "HCk2Q1BdaneEkZ6ruMXS3+z5BhMgLTpHVGFue4iVoq8=";
const KEY_B: &str = "IzA9SldkcX6LmKWyv8zZ5vMADRonNEFOW2h1go+cqbY=";

fn location(id: i64, mode: ProtoMode) -> ServiceLocation {
    ServiceLocation {
        name: format!("office {id}"),
        address: "10.0.0.2/24".into(),
        pubkey: KEY_B.into(),
        endpoint: "vpn.example.com:51820".into(),
        allowed_ips: "10.0.0.0/24, 10.1.0.0/16".into(),
        keepalive_interval: 25,
        dns: "10.0.0.53, corp.example".into(),
        mode: mode as i32,
        core_location_id: id,
        posture_check_required: false,
        mtu: Some(1380),
    }
}

fn request(locations: Vec<ServiceLocation>) -> SaveServiceLocationsRequest {
    SaveServiceLocationsRequest {
        service_locations: locations,
        instance_id: INSTANCE.to_uppercase(),
        private_key: KEY_A.into(),
        proxy_url: "https://edge".into(),
        device_pubkey: KEY_B.into(),
        token: Some("ignored".into()),
    }
}

#[test]
fn requests_are_validated_and_canonicalized() {
    let stored = StoredInstance::from_request(&request(vec![
        location(2, ProtoMode::AlwaysOn),
        location(1, ProtoMode::PreLogon),
        location(1, ProtoMode::PreLogon),
    ]))
    .unwrap();
    assert_eq!(stored.instance_id, INSTANCE, "UUID is lowercased");
    let ids: Vec<_> = stored.locations.iter().map(|l| l.network_id).collect();
    assert_eq!(ids, [1, 2], "sorted and deduplicated");
    assert_eq!(stored.locations[0].mode, Mode::PreLogon);
    assert_eq!(stored.locations[0].allowed_ips, "10.0.0.0/24,10.1.0.0/16");
    assert!(
        !format!("{stored:?}").contains(KEY_A),
        "private key redacted"
    );

    let reject = |change: &dyn Fn(&mut SaveServiceLocationsRequest)| {
        let mut bad = request(vec![location(1, ProtoMode::AlwaysOn)]);
        change(&mut bad);
        StoredInstance::from_request(&bad).unwrap_err()
    };
    assert!(matches!(
        reject(&|r| r.instance_id = "../../etc/passwd".into()),
        StoreError::Invalid {
            field: "instance_id",
            ..
        }
    ));
    assert!(matches!(
        reject(&|r| r.private_key = "short".into()),
        StoreError::Invalid {
            field: "private_key",
            ..
        }
    ));
    assert!(matches!(
        reject(&|r| r.service_locations[0].pubkey = "x".into()),
        StoreError::Invalid {
            field: "pubkey",
            ..
        }
    ));
    assert!(matches!(
        reject(&|r| r.service_locations[0].endpoint = "host-without-port".into()),
        StoreError::Invalid {
            field: "endpoint",
            ..
        }
    ));
    assert!(matches!(
        reject(&|r| r.service_locations[0].allowed_ips = "10.0.0.0/24; rm -rf".into()),
        StoreError::Invalid {
            field: "allowed_ips",
            ..
        }
    ));
    assert!(matches!(
        reject(&|r| r.service_locations[0].dns = "1.1.1.1\n$(id)".into()),
        StoreError::Invalid { field: "dns", .. }
    ));
    for bad_dns in ["--flag", "[bad]", "foo bar", "1.1.1.1, -bad"] {
        assert!(matches!(
            reject(&|r| r.service_locations[0].dns = bad_dns.into()),
            StoreError::Invalid { field: "dns", .. }
        ));
    }
    assert!(matches!(
        reject(&|r| r.service_locations[0].name = "bad\u{7}name".into()),
        StoreError::Invalid { field: "name", .. }
    ));
    assert!(matches!(
        reject(&|r| r.service_locations[0].mode = 7),
        StoreError::Invalid { field: "mode", .. }
    ));
    assert!(matches!(
        reject(&|r| r.service_locations[0].posture_check_required = true),
        StoreError::Invalid { .. }
    ));
    assert_eq!(
        reject(
            &|r| r.service_locations = (0..40).map(|i| location(i, ProtoMode::AlwaysOn)).collect()
        ),
        StoreError::TooManyLocations
    );

    // An MTU outside sane bounds is dropped, not stored.
    let mut odd = request(vec![location(1, ProtoMode::AlwaysOn)]);
    odd.service_locations[0].mtu = Some(10);
    assert_eq!(
        StoredInstance::from_request(&odd).unwrap().locations[0].mtu,
        None
    );
}

#[test]
fn endpoint_and_instance_id_syntax() {
    assert!(validate_endpoint("vpn.example.com:51820").is_ok());
    assert!(validate_endpoint("192.0.2.1:1").is_ok());
    assert!(validate_endpoint("[2001:db8::1]:51820").is_ok());
    for bad in [
        "vpn:0",
        "vpn:99999",
        ":51820",
        "[nope]:1",
        "a b:1",
        "vpn.example.com",
    ] {
        assert!(validate_endpoint(bad).is_err(), "{bad}");
    }
    assert!(validate_instance_id(INSTANCE).is_ok());
    for bad in [
        "",
        "not-a-uuid",
        "2b9a4b8e_8b8e_4d4e_9a3f_1c2d3e4f5a6b",
        "../x",
    ] {
        assert!(validate_instance_id(bad).is_err(), "{bad}");
    }
}

#[test]
fn store_saves_privately_and_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().join("service_locations"));
    let instance =
        StoredInstance::from_request(&request(vec![location(1, ProtoMode::AlwaysOn)])).unwrap();

    assert!(store.save(&instance).unwrap());
    assert!(
        !store.save(&instance).unwrap(),
        "unchanged save writes nothing"
    );
    let loaded = store.load_all();
    assert_eq!(loaded, std::slice::from_ref(&instance));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file = dir
            .path()
            .join("service_locations")
            .join(format!("{INSTANCE}.json"));
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(dir.path().join("service_locations"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    // A tampered file is ignored, not trusted.
    let file = dir
        .path()
        .join("service_locations")
        .join(format!("{INSTANCE}.json"));
    let tampered = std::fs::read_to_string(&file)
        .unwrap()
        .replace("vpn.example.com:51820", "vpn.example.com");
    std::fs::write(&file, tampered).unwrap();
    assert!(store.load_all().is_empty());

    // Tampered MTU, duplicate network ID, or lax permissions are also refused.
    let bad_mtu = serde_json::to_string_pretty(&instance)
        .unwrap()
        .replace("1380", "10");
    std::fs::write(&file, bad_mtu).unwrap();
    assert!(store.load_all().is_empty());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        store.save(&instance).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.load_all().is_empty());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    // An empty list deletes.
    store.save(&instance).unwrap();
    let mut empty = instance.clone();
    empty.locations.clear();
    assert!(store.save(&empty).unwrap());
    assert!(store.load_all().is_empty());
    assert!(!store.delete(INSTANCE).unwrap());
}

#[test]
fn interface_names_are_stable_short_and_distinct() {
    let a = TunnelKey {
        instance_id: INSTANCE.into(),
        network_id: 1,
    };
    let b = TunnelKey {
        instance_id: INSTANCE.into(),
        network_id: 2,
    };
    assert_eq!(interface_name(&a), interface_name(&a.clone()));
    assert_ne!(interface_name(&a), interface_name(&b));
    assert!(interface_name(&a).len() <= 15);
    assert!(interface_name(&a).starts_with("xgs"));
}

#[test]
fn pre_logon_runs_only_without_a_user() {
    assert!(wanted(Mode::AlwaysOn, true));
    assert!(wanted(Mode::AlwaysOn, false));
    assert!(wanted(Mode::PreLogon, false));
    assert!(!wanted(Mode::PreLogon, true));
}

#[test]
fn reconciler_plans_desired_versus_actual() {
    let stored = StoredInstance::from_request(&request(vec![
        location(1, ProtoMode::AlwaysOn),
        location(2, ProtoMode::PreLogon),
    ]))
    .unwrap();
    let desired = desired_tunnels(std::slice::from_ref(&stored));
    let key = |id| TunnelKey {
        instance_id: INSTANCE.into(),
        network_id: id,
    };
    let fingerprint = |id: i64| {
        desired
            .iter()
            .find(|t| t.key.network_id == id)
            .unwrap()
            .fingerprint
    };

    // Nothing running, nobody signed in: both come up.
    assert_eq!(
        plan(&desired, &HashMap::new(), false),
        [Action::Up(key(1)), Action::Up(key(2))]
    );
    // A user signs in: the pre-logon tunnel goes down, the always-on one stays.
    let running: HashMap<_, _> = [(key(1), fingerprint(1)), (key(2), fingerprint(2))].into();
    assert_eq!(plan(&desired, &running, true), [Action::Down(key(2))]);
    // Everything already right: nothing to do.
    assert!(plan(&desired, &running, false).is_empty());

    // Changed settings replace the tunnel; a removed location and a stale tunnel of an
    // unknown instance go down.
    let mut changed = stored.clone();
    changed.locations[0].endpoint = "other.example.com:51820".into();
    changed.locations.truncate(1);
    let desired = desired_tunnels(&[changed]);
    let stale = TunnelKey {
        instance_id: "00000000-0000-0000-0000-000000000000".into(),
        network_id: 9,
    };
    let running: HashMap<_, _> = [
        (key(1), fingerprint(1)),
        (key(2), fingerprint(2)),
        (stale.clone(), 1),
    ]
    .into();
    assert_eq!(
        plan(&desired, &running, false),
        [
            Action::Down(stale),
            Action::Down(key(2)),
            Action::Replace(key(1))
        ]
    );

    // A rotated device key also replaces the tunnel.
    let mut rotated = stored;
    rotated.private_key = KEY_B.into();
    let rotated = desired_tunnels(&[rotated]);
    assert_ne!(rotated[0].fingerprint, fingerprint(1));
}
