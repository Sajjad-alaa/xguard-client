use chrono::TimeZone;
use tempfile::tempdir;

use super::*;

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 18, 12, 0, 0).unwrap()
}

const VALID: &str = r#"{
  "version": 1,
  "instance_name": "XGuard",
  "enrollment_url": "https://edge.example.com/",
  "enrollment_token": "AbC123xyz",
  "expires_at": "2026-11-19T12:00:00Z",
  "username": "hpotter"
}"#;

#[test]
fn parses_xguard_and_legacy_files() {
    let config = parse_provisioning(VALID, now()).unwrap();
    assert_eq!(config.enrollment_url, "https://edge.example.com/");
    assert_eq!(config.enrollment_token, "AbC123xyz");
    assert!(
        !format!("{config:?}").contains("AbC123xyz"),
        "token is redacted"
    );

    // Defguard-style file, with a byte order mark as Windows editors write it.
    let legacy =
        "\u{FEFF}{\"enrollment_url\":\"https://edge.example.com\",\"enrollment_token\":\"tok\"}";
    assert_eq!(
        parse_provisioning(legacy, now()).unwrap().enrollment_token,
        "tok"
    );
}

#[test]
fn rejects_bad_files() {
    let replace = |from: &str, to: &str| VALID.replace(from, to);
    for (content, expected) in [
        (
            replace("2026-11-19T12", "2026-11-18T11"),
            ProvisioningError::Expired,
        ),
        (
            replace("\"version\": 1", "\"version\": 2"),
            ProvisioningError::Invalid("unsupported version 2".into()),
        ),
    ] {
        assert_eq!(parse_provisioning(&content, now()), Err(expected));
    }
    for content in [
        replace("https://edge", "http://edge"),
        replace(
            "https://edge.example.com/",
            "https://user:pw@edge.example.com/",
        ),
        replace("https://edge.example.com/", "javascript:alert(1)"),
        replace("AbC123xyz", ""),
        replace("AbC123xyz", "token with spaces"),
        replace("AbC123xyz", &"a".repeat(300)),
        replace("2026-11-19T12:00:00Z", "tomorrow"),
        replace("\"username\"", "\"unknown_field\""),
        "not json".to_owned(),
        "{}".to_owned(),
    ] {
        assert!(
            matches!(
                parse_provisioning(&content, now()),
                Err(ProvisioningError::Invalid(_))
            ),
            "{content}"
        );
    }
    // Plain HTTP is fine to a loopback Edge (development).
    assert!(parse_provisioning(
        &replace("https://edge.example.com", "http://127.0.0.1:8080"),
        now()
    )
    .is_ok());
}

#[cfg(unix)]
#[test]
fn user_files_must_be_private_and_not_links() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let dir = tempdir().unwrap();
    let path = dir.path().join(PROVISIONING_FILE_NAME);
    fs::write(&path, VALID).unwrap();

    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        read_provisioning(&path, Scope::User, now()),
        Err(ProvisioningError::Insecure(_))
    ));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(read_provisioning(&path, Scope::User, now()).is_ok());

    let link = dir.path().join("link.json");
    symlink(&path, &link).unwrap();
    assert!(matches!(
        read_provisioning(&link, Scope::User, now()),
        Err(ProvisioningError::Insecure(_))
    ));

    let big = dir.path().join("big.json");
    fs::write(
        &big,
        " ".repeat(usize::try_from(MAX_FILE_SIZE).unwrap() + 1),
    )
    .unwrap();
    fs::set_permissions(&big, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        read_provisioning(&big, Scope::User, now()),
        Err(ProvisioningError::TooLarge)
    );
    assert_eq!(
        read_provisioning(&dir.path().join("missing.json"), Scope::User, now()),
        Err(ProvisioningError::NotFound)
    );
}

#[cfg(unix)]
#[test]
fn system_files_must_be_root_owned_and_not_writable_by_others() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let path = dir.path().join(PROVISIONING_FILE_NAME);
    fs::write(&path, VALID).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

    if nix::unistd::geteuid().is_root() {
        assert!(read_provisioning(&path, Scope::System, now()).is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(
            read_provisioning(&path, Scope::System, now()),
            Err(ProvisioningError::Insecure(_))
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            read_provisioning(&path, Scope::System, now()),
            Err(ProvisioningError::Insecure(_))
        ));
    } else {
        // A file a normal user could have written is never trusted as a system file.
        assert!(matches!(
            read_provisioning(&path, Scope::System, now()),
            Err(ProvisioningError::Insecure(_))
        ));
    }
}

#[cfg(unix)]
#[test]
fn consumed_tokens_are_not_offered_again() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    let path = dir.path().join(PROVISIONING_FILE_NAME);
    fs::write(&path, VALID).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let found = find_provisioning(dir.path(), now()).expect("user file found");
    assert_eq!(found.scope, Scope::User);
    mark_consumed(dir.path(), &found);
    assert!(!path.exists(), "user file removed after enrollment");

    // The same token deployed again is skipped.
    fs::write(&path, VALID).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(find_provisioning(dir.path(), now()).is_none());
    let consumed = dir.path().join(CONSUMED_FILE_NAME);
    assert_eq!(
        fs::metadata(&consumed).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
