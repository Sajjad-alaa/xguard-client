//! Pure parsers for the output of the read-only probes in [`super::collect`].
//!
//! Every function takes text (or a directory tree) and returns `None` when it cannot tell, so a
//! surprising output never turns into a passing fact.

use std::{fs, path::Path};

/// `ENABLED=yes` in `/etc/ufw/ufw.conf`.
#[must_use]
pub fn ufw_enabled(conf: &str) -> Option<bool> {
    conf.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| line.strip_prefix("ENABLED="))
        .map(|value| {
            value
                .trim()
                .trim_matches(['"', '\''])
                .eq_ignore_ascii_case("yes")
        })
}

/// Output of `gsettings get … lock-enabled`: `true` or `false`.
#[must_use]
pub fn gsettings_bool(output: &str) -> Option<bool> {
    match output.trim() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// KDE `kscreenlockerrc`: `[Daemon] Autolock=false` disables the automatic lock (default on).
#[must_use]
pub fn kde_autolock(conf: Option<&str>) -> bool {
    let Some(conf) = conf else {
        return true;
    };
    let mut in_daemon = false;
    for line in conf.lines().map(str::trim) {
        if line.starts_with('[') {
            in_daemon = line == "[Daemon]";
        } else if in_daemon {
            if let Some(value) = line.strip_prefix("Autolock=") {
                return !value.trim().eq_ignore_ascii_case("false");
            }
        }
    }
    true
}

/// The root mount from `/proc/self/mountinfo`: its `major:minor` and mount source.
#[must_use]
pub fn root_mount(mountinfo: &str) -> Option<(u32, u32, String)> {
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // id parent major:minor root mount-point options ... - fstype source super-options
        if fields.len() < 10 || fields[4] != "/" {
            continue;
        }
        let (major, minor) = fields[2].split_once(':')?;
        let separator = fields.iter().position(|f| *f == "-")?;
        let source = fields.get(separator + 2)?.to_string();
        return Some((major.parse().ok()?, minor.parse().ok()?, source));
    }
    None
}

/// Whether the block device at `block_dir` (a `/sys/class/block/<name>` style directory) is a
/// dm-crypt mapping or sits on one (LVM on LUKS), following `slaves` up to a few levels.
#[must_use]
pub fn is_dm_crypt(block_dir: &Path) -> bool {
    fn walk(dir: &Path, depth: u8) -> bool {
        if depth > 4 {
            return false;
        }
        if let Ok(uuid) = fs::read_to_string(dir.join("dm/uuid")) {
            if uuid.trim_start().starts_with("CRYPT-") {
                return true;
            }
        }
        let Ok(entries) = fs::read_dir(dir.join("slaves")) else {
            return false;
        };
        entries
            .flatten()
            .take(16)
            .any(|entry| walk(&entry.path(), depth + 1))
    }
    walk(block_dir, 0)
}

/// `fdesetup status`: "FileVault is On." / "FileVault is Off.".
#[must_use]
pub fn filevault_on(output: &str) -> Option<bool> {
    let first = output.lines().next()?.trim();
    if first.starts_with("FileVault is On") {
        Some(true)
    } else if first.starts_with("FileVault is Off") {
        Some(false)
    } else {
        None
    }
}

/// `socketfilterfw --getglobalstate`: "Firewall is enabled. (State = 1)".
#[must_use]
pub fn macos_firewall_enabled(output: &str) -> Option<bool> {
    let output = output.trim();
    if let Some(state) = output
        .split("State = ")
        .nth(1)
        .and_then(|rest| rest.chars().next())
        .and_then(|c| c.to_digit(10))
    {
        return Some(state >= 1);
    }
    if output.contains("is enabled") {
        Some(true)
    } else if output.contains("is disabled") {
        Some(false)
    } else {
        None
    }
}

/// `sysadminctl -screenLock status`: "screenLock delay is immediate" or "screenLock is off".
#[must_use]
pub fn macos_screen_lock(output: &str) -> Option<bool> {
    let line = output.lines().find(|line| line.contains("screenLock"))?;
    if line.contains("screenLock is off") {
        Some(false)
    } else if line.contains("screenLock delay is") {
        Some(true)
    } else {
        None
    }
}

/// `csrutil status`: "System Integrity Protection status: enabled.".
#[must_use]
pub fn sip_enabled(output: &str) -> Option<bool> {
    let status = output.split("status:").nth(1)?.trim_start();
    if status.starts_with("enabled") {
        Some(true)
    } else if status.starts_with("disabled") {
        Some(false)
    } else {
        None
    }
}

/// One `key=value` line from the Windows probe script.
fn report_value<'a>(report: &'a str, key: &str) -> Option<&'a str> {
    report.lines().find_map(|line| {
        let (k, v) = line.trim().split_once('=')?;
        (k == key).then_some(v.trim())
    })
}

fn report_bool(report: &str, key: &str) -> Option<bool> {
    match report_value(report, key)? {
        "1" | "True" | "true" => Some(true),
        "0" | "False" | "false" => Some(false),
        _ => None,
    }
}

fn report_int(report: &str, key: &str) -> Option<i64> {
    report_value(report, key)?.parse().ok()
}

/// Facts from the Windows probe script (see `collect::WINDOWS_SCRIPT`).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct WindowsReport {
    pub disk_encrypted: Option<bool>,
    pub firewall_enabled: Option<bool>,
    pub screen_lock_enabled: Option<bool>,
    pub antivirus_enabled: Option<bool>,
    pub domain_joined: Option<bool>,
    pub security_update_age_days: Option<u32>,
}

/// Parses the `key=value` report printed by the Windows probe script.
#[must_use]
pub fn windows_report(report: &str) -> WindowsReport {
    // Shell.Application System.Volume.BitLockerProtection: 1 on, 6 on and locked; 2 off,
    // 3 encrypting, 4 decrypting, 5 suspended, 0 cannot be encrypted.
    let disk_encrypted = report_int(report, "bitlocker").and_then(|state| match state {
        1 | 6 => Some(true),
        0 | 2..=5 | 7 | 8 => Some(false),
        _ => None,
    });
    // Each profile is 1 (on) or 0 (off); a policy value wins over the local one.
    let profiles: Vec<Option<bool>> = ["domain", "private", "public"]
        .iter()
        .map(|profile| {
            report_bool(report, &format!("fw_policy_{profile}"))
                .or_else(|| report_bool(report, &format!("fw_{profile}")))
        })
        .collect();
    let firewall_enabled = if profiles.iter().any(|p| *p == Some(false)) {
        Some(false)
    } else if profiles.iter().all(|p| *p == Some(true)) {
        Some(true)
    } else {
        None
    };
    let secure_saver = report_bool(report, "saver_policy_active")
        .or_else(|| report_bool(report, "saver_active"))
        == Some(true)
        && report_bool(report, "saver_policy_secure")
            .or_else(|| report_bool(report, "saver_secure"))
            == Some(true);
    let inactivity_lock = report_int(report, "inactivity_timeout").is_some_and(|secs| secs > 0);
    let screen_lock_enabled = Some(secure_saver || inactivity_lock);
    // SecurityCenter2 productState: bits 12-15 are 1 when the product is enabled.
    let antivirus_enabled = report_value(report, "av_states").map(|states| {
        states
            .split(',')
            .filter_map(|s| s.trim().parse::<u32>().ok())
            .any(|state| (state >> 12) & 0xF == 1)
    });
    let security_update_age_days =
        report_int(report, "update_age_days").and_then(|days| u32::try_from(days).ok());
    WindowsReport {
        disk_encrypted,
        firewall_enabled,
        screen_lock_enabled,
        antivirus_enabled,
        domain_joined: report_bool(report, "domain_joined"),
        security_update_age_days,
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{create_dir_all, write};

    use super::*;

    #[test]
    fn ufw() {
        assert_eq!(
            ufw_enabled("# comment\nENABLED=yes\nLOGLEVEL=low\n"),
            Some(true)
        );
        assert_eq!(ufw_enabled("ENABLED=no"), Some(false));
        assert_eq!(ufw_enabled("#ENABLED=yes\n"), None);
        assert_eq!(ufw_enabled("ENABLED=\"yes\""), Some(true));
    }

    #[test]
    fn screen_lock_linux() {
        assert_eq!(gsettings_bool("true\n"), Some(true));
        assert_eq!(gsettings_bool("false"), Some(false));
        assert_eq!(gsettings_bool("No such schema"), None);
        assert!(kde_autolock(None));
        assert!(kde_autolock(Some("[Daemon]\nTimeout=5\n")));
        assert!(!kde_autolock(Some(
            "[Greeter]\nAutolock=true\n[Daemon]\nAutolock=false\n"
        )));
        assert!(kde_autolock(Some("[Other]\nAutolock=false\n")));
    }

    #[test]
    fn mountinfo_root() {
        let mountinfo = "\
22 1 0:21 / /proc rw,nosuid shared:5 - proc proc rw
29 1 253:1 / / rw,relatime shared:1 - ext4 /dev/mapper/vg-root rw
30 29 259:2 / /boot rw shared:2 - ext4 /dev/nvme0n1p2 rw";
        assert_eq!(
            root_mount(mountinfo),
            Some((253, 1, "/dev/mapper/vg-root".to_string()))
        );
        let btrfs = "29 1 0:33 /@ / rw,relatime shared:1 - btrfs /dev/mapper/luks-1 rw";
        assert_eq!(
            root_mount(btrfs),
            Some((0, 33, "/dev/mapper/luks-1".into()))
        );
        assert_eq!(root_mount("garbage"), None);
    }

    #[test]
    fn dm_crypt_detection() {
        let sys = tempfile::tempdir().unwrap();
        // dm-1 (LVM) on dm-0 (LUKS) on nvme0n1p3.
        let dm0 = sys.path().join("dm-0");
        let dm1 = sys.path().join("dm-1");
        let plain = sys.path().join("nvme0n1p3");
        create_dir_all(dm0.join("dm")).unwrap();
        create_dir_all(dm1.join("dm")).unwrap();
        create_dir_all(dm1.join("slaves/dm-0/dm")).unwrap();
        create_dir_all(&plain).unwrap();
        write(dm0.join("dm/uuid"), "CRYPT-LUKS2-abc-luks\n").unwrap();
        write(dm1.join("dm/uuid"), "LVM-xyz\n").unwrap();
        write(dm1.join("slaves/dm-0/dm/uuid"), "CRYPT-LUKS2-abc-luks\n").unwrap();
        assert!(is_dm_crypt(&dm0));
        assert!(is_dm_crypt(&dm1));
        assert!(!is_dm_crypt(&plain));
        assert!(!is_dm_crypt(&sys.path().join("missing")));
    }

    #[test]
    fn macos_outputs() {
        assert_eq!(filevault_on("FileVault is On.\n"), Some(true));
        assert_eq!(filevault_on("FileVault is Off.\n"), Some(false));
        assert_eq!(filevault_on("Encryption in progress"), None);
        assert_eq!(
            macos_firewall_enabled("Firewall is enabled. (State = 1)"),
            Some(true)
        );
        assert_eq!(
            macos_firewall_enabled(
                "Firewall is blocking all non-essential incoming connections. (State = 2)"
            ),
            Some(true)
        );
        assert_eq!(
            macos_firewall_enabled("Firewall is disabled. (State = 0)"),
            Some(false)
        );
        assert_eq!(macos_firewall_enabled(""), None);
        assert_eq!(
            macos_screen_lock("2026-11-18 sysadminctl[1:2] screenLock delay is immediate\n"),
            Some(true)
        );
        assert_eq!(
            macos_screen_lock("sysadminctl[1:2] screenLock is off\n"),
            Some(false)
        );
        assert_eq!(macos_screen_lock("unknown"), None);
        assert_eq!(
            sip_enabled("System Integrity Protection status: enabled."),
            Some(true)
        );
        assert_eq!(
            sip_enabled("System Integrity Protection status: disabled."),
            Some(false)
        );
        assert_eq!(sip_enabled("csrutil: command not found"), None);
    }

    #[test]
    fn windows_outputs() {
        let report = "\
bitlocker=1
fw_domain=1
fw_private=1
fw_public=1
saver_active=1
saver_secure=1
av_states=397568,393472
domain_joined=True
update_age_days=12
";
        assert_eq!(
            windows_report(report),
            WindowsReport {
                disk_encrypted: Some(true),
                firewall_enabled: Some(true),
                screen_lock_enabled: Some(true),
                antivirus_enabled: Some(true),
                domain_joined: Some(true),
                security_update_age_days: Some(12),
            }
        );

        // A policy that turns a profile off wins; disabled antivirus (state 393472 = 0x60100).
        let report = "bitlocker=2\nfw_domain=1\nfw_private=1\nfw_public=1\nfw_policy_public=0\n\
                      av_states=393472\ninactivity_timeout=900\ndomain_joined=False\n";
        let parsed = windows_report(report);
        assert_eq!(parsed.disk_encrypted, Some(false));
        assert_eq!(parsed.firewall_enabled, Some(false));
        assert_eq!(parsed.antivirus_enabled, Some(false));
        assert_eq!(parsed.screen_lock_enabled, Some(true));
        assert_eq!(parsed.domain_joined, Some(false));
        assert_eq!(parsed.security_update_age_days, None);

        // Nothing readable: unknown, never a pass (screen lock is "not configured").
        let parsed = windows_report("bitlocker=\nupdate_age_days=-3\n");
        assert_eq!(parsed.disk_encrypted, None);
        assert_eq!(parsed.firewall_enabled, None);
        assert_eq!(parsed.antivirus_enabled, None);
        assert_eq!(parsed.screen_lock_enabled, Some(false));
        assert_eq!(parsed.security_update_age_days, None);
    }
}
