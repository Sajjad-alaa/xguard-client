//! Pure parsers for the output of the read-only probes in [`super::collect`].
//!
//! Every function takes text (or a directory tree) and returns `None` when it cannot tell, so a
//! surprising output never turns into a passing fact.

use std::{fs, path::Path};

use chrono::{DateTime, NaiveDateTime, Utc};

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

/// Output of `gsettings get org.gnome.desktop.session idle-delay`: `uint32 <secs>`.
/// Zero disables screen blanking / locking.
#[must_use]
pub fn gnome_idle_delay_nonzero(output: &str) -> Option<bool> {
    let secs: u32 = output.trim().strip_prefix("uint32")?.trim().parse().ok()?;
    Some(secs > 0)
}

/// KDE `kscreenlockerrc`: `[Daemon] Autolock=false` disables the automatic lock; `None` if unreadable.
#[must_use]
pub fn kde_autolock(conf: Option<&str>) -> Option<bool> {
    let conf = conf?;
    let mut in_daemon = false;
    for line in conf.lines().map(str::trim) {
        if line.starts_with('[') {
            in_daemon = line == "[Daemon]";
        } else if in_daemon {
            if let Some(value) = line.strip_prefix("Autolock=") {
                return Some(!value.trim().eq_ignore_ascii_case("false"));
            }
        }
    }
    Some(true)
}

/// The root mount from `/proc/self/mountinfo`: its `major:minor` and mount source.
/// Picks the last `/` mount entry and skips initial `rootfs` mounts.
#[must_use]
pub fn root_mount(mountinfo: &str) -> Option<(u32, u32, String)> {
    let mut found = None;
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // id parent major:minor root mount-point options ... - fstype source super-options
        if fields.len() < 10 || fields[4] != "/" {
            continue;
        }
        let Some(separator) = fields.iter().position(|f| *f == "-") else {
            continue;
        };
        let Some(&fstype) = fields.get(separator + 1) else {
            continue;
        };
        if fstype == "rootfs" {
            continue;
        }
        let (Some((major, minor)), Some(source)) =
            (fields[2].split_once(':'), fields.get(separator + 2))
        else {
            continue;
        };
        let (Ok(major), Ok(minor)) = (major.parse(), minor.parse()) else {
            continue;
        };
        found = Some((major, minor, (*source).to_string()));
    }
    found
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
/// Rejects custom configurations such as `"enabled (Custom Configuration)."` so SIP must be fully on.
#[must_use]
pub fn sip_enabled(output: &str) -> Option<bool> {
    let status = output.split("status:").nth(1)?.trim();
    if status == "enabled." || status == "enabled" {
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
    let firewall_enabled = if profiles.contains(&Some(false)) {
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

// ---------------------------------------------------------------------------------------------
// Antivirus / EDR agents (macOS and Linux)
// ---------------------------------------------------------------------------------------------

/// Process names of antivirus and EDR agents recognised on Linux. Matched against
/// `/proc/<pid>/comm` (which the kernel truncates to 15 bytes) of processes owned by a system
/// account. Keep in sync with `docs/device-posture.md`.
pub const LINUX_SECURITY_AGENTS: &[&str] = &[
    "clamd",                  // ClamAV daemon
    "clamonacc",              // ClamAV on-access scanner
    "falcon-sensor",          // CrowdStrike Falcon
    "wdavdaemon",             // Microsoft Defender for Endpoint
    "s1-agent",               // SentinelOne
    "sophos_threat_detector", // Sophos Protection for Linux
    "savd",                   // Sophos Anti-Virus for Linux (legacy)
    "ds_agent",               // Trend Micro Deep Security / Server & Workload Protection
    "cbagentd",               // VMware Carbon Black Cloud
    "elastic-endpoint",       // Elastic Defend
];

/// Executable names of antivirus and EDR agents recognised on macOS. The built-in XProtect does
/// not count: it is always present and does not mean an endpoint product is deployed.
/// Keep in sync with `docs/device-posture.md`.
pub const MACOS_SECURITY_AGENTS: &[&str] = &[
    "wdavdaemon",                        // Microsoft Defender for Endpoint
    "wdavdaemon_enterprise",             // Microsoft Defender for Endpoint
    "com.crowdstrike.falcon.Agent",      // CrowdStrike Falcon (system extension)
    "sentineld",                         // SentinelOne
    "SophosScanD",                       // Sophos
    "com.sophos.endpoint.scanextension", // Sophos (system extension)
    "JamfProtect",                       // Jamf Protect
    "com.jamf.protect.daemon",           // Jamf Protect (system extension)
    "esets_daemon",                      // ESET Endpoint Security
    "BDLDaemon",                         // Bitdefender
    "RTProtectionDaemon",                // Malwarebytes
    "CbOsxSensorService",                // VMware Carbon Black
    "clamd",                             // ClamAV
];

/// Length to which Linux truncates `comm`.
const LINUX_COMM_LEN: usize = 15;

/// Whether a process called `name` is one of `agents`. A name of exactly `truncated_at` bytes
/// may be a cut-off longer name, so it also matches agents that start with it.
#[must_use]
pub fn is_security_agent(name: &str, agents: &[&str], truncated_at: Option<usize>) -> bool {
    agents.iter().any(|agent| {
        *agent == name
            || truncated_at.is_some_and(|len| {
                name.len() == len && agent.len() > len && agent.starts_with(name)
            })
    })
}

/// Whether any of the Linux process names (from `/proc/<pid>/comm`) is a security agent.
#[must_use]
pub fn linux_security_agent_running<'a>(names: impl IntoIterator<Item = &'a str>) -> bool {
    names
        .into_iter()
        .any(|name| is_security_agent(name.trim(), LINUX_SECURITY_AGENTS, Some(LINUX_COMM_LEN)))
}

/// Below this uid macOS accounts are system accounts (users start at 501).
const MACOS_SYSTEM_UID_LIMIT: u32 = 500;

/// `ps -axo uid=,comm=` on macOS: whether a security agent runs under a system account.
/// `None` when the output does not look like a process list.
#[must_use]
pub fn macos_security_agent_running(ps_output: &str) -> Option<bool> {
    let mut processes = 0usize;
    let mut found = false;
    for line in ps_output.lines() {
        let line = line.trim();
        let Some((uid, command)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let Ok(uid) = uid.parse::<u32>() else {
            continue;
        };
        processes += 1;
        let name = command.trim().rsplit('/').next().unwrap_or_default();
        if uid < MACOS_SYSTEM_UID_LIMIT && is_security_agent(name, MACOS_SECURITY_AGENTS, Some(16))
        {
            found = true;
        }
    }
    // A real system always has more than a handful of processes (launchd, kernel_task, ...).
    (processes >= 5).then_some(found)
}

// ---------------------------------------------------------------------------------------------
// Directory membership
// ---------------------------------------------------------------------------------------------

/// `dsconfigad -show`: lists the Active Directory binding, prints nothing when not bound.
#[must_use]
pub fn macos_ad_bound(output: &str) -> Option<bool> {
    let output = output.trim();
    if output.is_empty() {
        return Some(false);
    }
    let domain = output.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key.trim() == "Active Directory Domain").then(|| value.trim())
    });
    domain.map(|domain| !domain.is_empty())
}

/// `dscl localhost -list /LDAPv3`: one configured LDAP server per line, nothing when none.
#[must_use]
pub fn macos_ldap_bound(output: &str) -> Option<bool> {
    let lines: Vec<&str> = output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if lines
        .iter()
        .any(|line| line.contains("Error") || line.contains("eDS") || line.contains("not found"))
    {
        return None;
    }
    Some(lines.iter().any(|line| {
        line.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
    }))
}

/// macOS directory membership: bound to AD or to an LDAP directory. Active Directory is the
/// primary signal; an unreadable LDAP list does not hide a known AD state.
#[must_use]
pub fn macos_domain_joined(ad: Option<bool>, ldap: Option<bool>) -> Option<bool> {
    match (ad, ldap) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), _) => Some(false),
        (None, _) => None,
    }
}

/// What the Linux probes found about directory membership.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LinuxDirectory {
    /// `/etc/krb5.keytab` exists and is not empty (written by `realm join`, `adcli join`,
    /// `net ads join` and `ipa-client-install`; readable by root only, so only its size is used).
    pub host_keytab: bool,
    /// `/etc/ipa/default.conf` exists (FreeIPA / Red Hat IdM client).
    pub ipa_client: bool,
    /// `sssd` runs as root.
    pub sssd_running: bool,
    /// `winbindd` runs as root.
    pub winbind_running: bool,
}

/// Joined through realmd/SSSD or winbind: a host keytab plus the daemon that uses it, or a
/// FreeIPA enrollment with SSSD. A keytab without a running daemon (left over from an old join)
/// does not count.
#[must_use]
pub fn linux_domain_joined(found: LinuxDirectory) -> bool {
    let daemon = found.sssd_running || found.winbind_running;
    daemon && (found.host_keytab || (found.ipa_client && found.sssd_running))
}

// ---------------------------------------------------------------------------------------------
// Last security update (macOS and Linux)
// ---------------------------------------------------------------------------------------------

/// Whole days from `then` to `now`; a timestamp in the future (clock skew) counts as today.
#[must_use]
pub fn age_days(then: NaiveDateTime, now: NaiveDateTime) -> Option<u32> {
    u32::try_from((now - then).num_days().max(0)).ok()
}

/// Names in the macOS install history that are OS or security updates. Background data
/// updates (XProtect, MRT, Gatekeeper, ...) arrive almost daily and say nothing about patching.
fn is_macos_os_update(name: &str) -> bool {
    let name = name.trim();
    [
        "macOS",
        "OS X",
        "Mac OS X",
        "Security Update",
        "Rapid Security Response",
        "Background Security Improvement",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

/// `/Library/Receipts/InstallHistory.plist`: when the newest macOS or security update was
/// installed (UTC). `None` when the history cannot be read or has no such entry.
#[must_use]
pub fn macos_last_os_update(plist_bytes: &[u8]) -> Option<NaiveDateTime> {
    let value = plist::Value::from_reader(std::io::Cursor::new(plist_bytes)).ok()?;
    value
        .as_array()?
        .iter()
        .filter_map(plist::Value::as_dictionary)
        .filter(|entry| {
            entry
                .get("displayName")
                .and_then(plist::Value::as_string)
                .is_some_and(is_macos_os_update)
        })
        .filter_map(|entry| entry.get("date").and_then(plist::Value::as_date))
        .map(|date| DateTime::<Utc>::from(std::time::SystemTime::from(date)).naive_utc())
        .max()
}

fn parse_local(text: &str, formats: &[&str]) -> Option<NaiveDateTime> {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    formats
        .iter()
        .find_map(|format| NaiveDateTime::parse_from_str(&text, format).ok())
}

/// `/var/log/apt/history.log`: the end of the newest transaction that upgraded packages
/// (local time). Installs and removals alone do not count.
#[must_use]
pub fn apt_last_upgrade(history: &str) -> Option<NaiveDateTime> {
    let mut newest = None;
    let mut start = None;
    let mut upgraded = false;
    for line in history.lines() {
        if let Some(date) = line.strip_prefix("Start-Date:") {
            start = parse_local(date, &["%Y-%m-%d %H:%M:%S"]);
            upgraded = false;
        } else if line.starts_with("Upgrade:") {
            upgraded = true;
        } else if let Some(date) = line.strip_prefix("End-Date:") {
            if upgraded {
                let end = parse_local(date, &["%Y-%m-%d %H:%M:%S"]).or(start);
                newest = newest.max(end);
            }
            upgraded = false;
            start = None;
        }
    }
    // A transaction still running (no End-Date yet) counts from its start.
    if upgraded {
        newest = newest.max(start);
    }
    newest
}

/// `/var/log/dpkg.log`: the newest `upgrade` action (local time).
#[must_use]
pub fn dpkg_last_upgrade(log: &str) -> Option<NaiveDateTime> {
    log.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let (date, time, action) = (fields.next()?, fields.next()?, fields.next()?);
            (action == "upgrade")
                .then(|| parse_local(&format!("{date} {time}"), &["%Y-%m-%d %H:%M:%S"]))
                .flatten()
        })
        .max()
}

/// `/var/log/pacman.log`: the newest `upgraded` entry (local time). Accepts the current
/// `[2024-11-20T10:23:45+0100]` and the older `[2019-03-01 10:23]` timestamps.
#[must_use]
pub fn pacman_last_upgrade(log: &str) -> Option<NaiveDateTime> {
    log.lines()
        .filter(|line| line.contains("] upgraded "))
        .filter_map(|line| {
            let stamp = line.strip_prefix('[')?.split_once(']')?.0;
            DateTime::parse_from_str(stamp, "%Y-%m-%dT%H:%M:%S%z")
                .map(|date| date.naive_local())
                .ok()
                .or_else(|| parse_local(stamp, &["%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S"]))
        })
        .max()
}

/// `rpm -qa --qf '%{INSTALLTIME}\n'`: the newest package install or update (UTC). RPM does not
/// record whether an update was a security fix, so any package change counts.
#[must_use]
pub fn rpm_newest_install(output: &str) -> Option<NaiveDateTime> {
    let mut count = 0usize;
    let newest = output
        .lines()
        .filter_map(|line| line.trim().parse::<i64>().ok())
        .inspect(|_| count += 1)
        .filter(|secs| *secs > 0)
        .max()?;
    // A system has hundreds of packages; a single number is probably an error message.
    if count < 10 {
        return None;
    }
    DateTime::from_timestamp(newest, 0).map(|date| date.naive_utc())
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
        assert_eq!(gnome_idle_delay_nonzero("uint32 300\n"), Some(true));
        assert_eq!(gnome_idle_delay_nonzero("uint32 0\n"), Some(false));
        assert_eq!(gnome_idle_delay_nonzero("garbage"), None);
        assert_eq!(kde_autolock(None), None);
        assert_eq!(kde_autolock(Some("[Daemon]\nTimeout=5\n")), Some(true));
        assert_eq!(
            kde_autolock(Some("[Greeter]\nAutolock=true\n[Daemon]\nAutolock=false\n")),
            Some(false)
        );
        assert_eq!(kde_autolock(Some("[Other]\nAutolock=false\n")), Some(true));
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
        let initramfs_then_real = "\
1 0 0:1 / / rw - rootfs rootfs rw
29 1 253:2 / / rw,relatime - ext4 /dev/mapper/cryptroot rw";
        assert_eq!(
            root_mount(initramfs_then_real),
            Some((253, 2, "/dev/mapper/cryptroot".to_string()))
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

    #[test]
    fn security_agents_linux() {
        // `/proc/<pid>/comm` values; long names are cut to 15 bytes by the kernel.
        let idle = [
            "systemd",
            "systemd-journal",
            "sshd",
            "NetworkManager",
            "firewalld",
        ];
        assert!(!linux_security_agent_running(idle));
        for agent in [
            "falcon-sensor",
            "wdavdaemon",
            "clamd",
            "s1-agent",
            "elastic-endpoin",
            "sophos_threat_d",
            "cbagentd\n",
        ] {
            let names = ["systemd", "sshd", agent];
            assert!(linux_security_agent_running(names), "{agent}");
        }
        // A 15-byte name that is not the start of an agent does not match.
        assert!(!linux_security_agent_running(["elastic-search1"]));
        assert!(!linux_security_agent_running(["clam"]));
    }

    #[test]
    fn security_agents_macos() {
        let ps = "\
    0 /sbin/launchd
    0 /usr/libexec/logd
    0 /usr/libexec/UserEventAgent
   88 /System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow
  501 /System/Library/CoreServices/Dock.app/Contents/MacOS/Dock
  501 /Applications/Safari.app/Contents/MacOS/Safari
";
        assert_eq!(macos_security_agent_running(ps), Some(false));
        let falcon = format!(
            "{ps}    0 /Library/SystemExtensions/6A4B54C1-2F2B-4D6E-9F0A-6E0A2B7C1D11/\
             com.crowdstrike.falcon.Agent.systemextension/Contents/MacOS/\
             com.crowdstrike.falcon.Agent\n"
        );
        assert_eq!(macos_security_agent_running(&falcon), Some(true));
        let defender =
            format!("{ps}    0 /Library/Application Support/Microsoft/Defender/wdavdaemon\n");
        assert_eq!(macos_security_agent_running(&defender), Some(true));
        let sentinel =
            format!("{ps}    0 /Library/Sentinel/sentinel-agent.bundle/Contents/MacOS/sentineld\n");
        assert_eq!(macos_security_agent_running(&sentinel), Some(true));
        // The same name started by a user does not count.
        let fake = format!("{ps}  501 /Users/alice/bin/sentineld\n");
        assert_eq!(macos_security_agent_running(&fake), Some(false));
        // Not a process list.
        assert_eq!(
            macos_security_agent_running("ps: illegal option -- x\n"),
            None
        );
        assert_eq!(macos_security_agent_running(""), None);
    }

    #[test]
    fn directory_macos() {
        let bound = "\
Active Directory Forest          = corp.example.com
Active Directory Domain          = corp.example.com
Computer Account                 = mac-0042$

Advanced Options - User Experience
  Create mobile account at login = Enabled
     Require confirmation        = Disabled
  Force home to startup disk     = Enabled
  Default user Shell             = /bin/bash

Advanced Options - Administrative
  Preferred Domain controller    = not set
  Allowed admin groups           = CORP\\Domain Admins
  Namespace mode                 = domain
";
        assert_eq!(macos_ad_bound(bound), Some(true));
        assert_eq!(macos_ad_bound(""), Some(false));
        assert_eq!(macos_ad_bound("\n"), Some(false));
        assert_eq!(macos_ad_bound("dsconfigad: Operation not permitted"), None);

        assert_eq!(macos_ldap_bound("ldap.example.com\n"), Some(true));
        assert_eq!(macos_ldap_bound(""), Some(false));
        assert_eq!(
            macos_ldap_bound(
                "list: Invalid Path\n<dscl_cmd> DS Error: -14009 (eDSUnknownNodeName)\n"
            ),
            None
        );

        assert_eq!(macos_domain_joined(Some(true), None), Some(true));
        assert_eq!(macos_domain_joined(Some(false), Some(true)), Some(true));
        assert_eq!(macos_domain_joined(None, Some(true)), Some(true));
        assert_eq!(macos_domain_joined(Some(false), None), Some(false));
        assert_eq!(macos_domain_joined(Some(false), Some(false)), Some(false));
        assert_eq!(macos_domain_joined(None, Some(false)), None);
    }

    #[test]
    fn directory_linux() {
        let realm_joined = LinuxDirectory {
            host_keytab: true,
            sssd_running: true,
            ..Default::default()
        };
        assert!(linux_domain_joined(realm_joined));
        assert!(linux_domain_joined(LinuxDirectory {
            host_keytab: true,
            winbind_running: true,
            ..Default::default()
        }));
        assert!(linux_domain_joined(LinuxDirectory {
            ipa_client: true,
            sssd_running: true,
            ..Default::default()
        }));
        // Left over from an old join, or SSSD for local caching only.
        assert!(!linux_domain_joined(LinuxDirectory {
            host_keytab: true,
            ..Default::default()
        }));
        assert!(!linux_domain_joined(LinuxDirectory {
            sssd_running: true,
            ..Default::default()
        }));
        assert!(!linux_domain_joined(LinuxDirectory {
            ipa_client: true,
            winbind_running: true,
            ..Default::default()
        }));
        assert!(!linux_domain_joined(LinuxDirectory::default()));
    }

    fn at(text: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S").unwrap()
    }

    #[test]
    fn update_age() {
        let now = at("2026-11-24 12:00:00");
        assert_eq!(age_days(at("2026-11-24 01:00:00"), now), Some(0));
        assert_eq!(age_days(at("2026-11-10 12:00:00"), now), Some(14));
        assert_eq!(age_days(at("2026-11-30 12:00:00"), now), Some(0));
    }

    const INSTALL_HISTORY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
	<dict>
		<key>date</key>
		<date>2026-06-12T08:01:44Z</date>
		<key>displayName</key>
		<string>macOS Sequoia 15.5</string>
		<key>displayVersion</key>
		<string>15.5</string>
		<key>processName</key>
		<string>softwareupdated</string>
	</dict>
	<dict>
		<key>date</key>
		<date>2026-09-30T19:22:03Z</date>
		<key>displayName</key>
		<string>macOS Sequoia 15.7.1</string>
		<key>displayVersion</key>
		<string>15.7.1</string>
		<key>packageIdentifiers</key>
		<array>
			<string>com.apple.pkg.update.os.15.7.1</string>
		</array>
		<key>processName</key>
		<string>softwareupdated</string>
	</dict>
	<dict>
		<key>date</key>
		<date>2026-11-20T03:11:02Z</date>
		<key>displayName</key>
		<string>XProtectPlistConfigData</string>
		<key>displayVersion</key>
		<string>5321</string>
		<key>processName</key>
		<string>softwareupdated</string>
	</dict>
	<dict>
		<key>date</key>
		<date>2026-11-21T03:12:45Z</date>
		<key>displayName</key>
		<string>Gatekeeper Compatibility Data</string>
		<key>displayVersion</key>
		<string>181</string>
		<key>processName</key>
		<string>softwareupdated</string>
	</dict>
	<dict>
		<key>date</key>
		<date>2026-11-22T10:00:00Z</date>
		<key>displayName</key>
		<string>Slack</string>
		<key>processName</key>
		<string>appstoreagent</string>
	</dict>
</array>
</plist>
"#;

    #[test]
    fn macos_install_history() {
        assert_eq!(
            macos_last_os_update(INSTALL_HISTORY.as_bytes()),
            Some(at("2026-09-30 19:22:03"))
        );
        // Background data updates and apps only: no OS update known.
        let data_only = INSTALL_HISTORY.replace("macOS Sequoia", "Safari");
        assert_eq!(macos_last_os_update(data_only.as_bytes()), None);
        let security = INSTALL_HISTORY.replace(
            "<string>Slack</string>",
            "<string>Background Security Improvement 26.1 (a)</string>",
        );
        assert_eq!(
            macos_last_os_update(security.as_bytes()),
            Some(at("2026-11-22 10:00:00"))
        );
        assert_eq!(macos_last_os_update(b"not a plist"), None);
        assert_eq!(macos_last_os_update(b""), None);
    }

    #[test]
    fn apt_history() {
        let history = "\
Start-Date: 2026-10-02  09:14:11
Commandline: apt-get -y install htop
Requested-By: alice (1000)
Install: htop:amd64 (3.3.0-4build1)
End-Date: 2026-10-02  09:14:13

Start-Date: 2026-11-03  06:25:40
Commandline: /usr/bin/unattended-upgrade
Upgrade: libssl3t64:amd64 (3.0.13-0ubuntu3.5, 3.0.13-0ubuntu3.6), openssl:amd64 (3.0.13-0ubuntu3.5, 3.0.13-0ubuntu3.6)
End-Date: 2026-11-03  06:25:52

Start-Date: 2026-11-18  14:02:09
Commandline: apt remove cowsay
Requested-By: alice (1000)
Remove: cowsay:amd64 (3.03+dfsg2-8)
End-Date: 2026-11-18  14:02:10
";
        assert_eq!(apt_last_upgrade(history), Some(at("2026-11-03 06:25:52")));
        assert_eq!(apt_last_upgrade(""), None);
        let running = "Start-Date: 2026-11-20  10:00:00\nUpgrade: curl:amd64 (8.5.0-2ubuntu10.4, 8.5.0-2ubuntu10.5)\n";
        assert_eq!(apt_last_upgrade(running), Some(at("2026-11-20 10:00:00")));
    }

    #[test]
    fn dpkg_log() {
        let log = "\
2026-11-03 06:25:41 startup archives unpack
2026-11-03 06:25:42 upgrade libssl3t64:amd64 3.0.13-0ubuntu3.5 3.0.13-0ubuntu3.6
2026-11-03 06:25:42 status half-configured libssl3t64:amd64 3.0.13-0ubuntu3.5
2026-11-03 06:25:43 status unpacked libssl3t64:amd64 3.0.13-0ubuntu3.6
2026-11-18 14:02:10 remove cowsay:amd64 3.03+dfsg2-8 <none>
2026-11-19 08:00:01 install htop:amd64 <none> 3.3.0-4build1
";
        assert_eq!(dpkg_last_upgrade(log), Some(at("2026-11-03 06:25:42")));
        assert_eq!(dpkg_last_upgrade("garbage\n"), None);
    }

    #[test]
    fn pacman_log() {
        let log = "\
[2019-03-01 10:23] [ALPM] upgraded bash (5.0.0-1 -> 5.0.002-1)
[2026-11-12T19:05:31+0100] [PACMAN] Running 'pacman -Syu'
[2026-11-12T19:05:40+0100] [ALPM] upgraded linux (6.11.7.arch1-1 -> 6.11.8.arch1-1)
[2026-11-12T19:05:41+0100] [ALPM] upgraded openssl (3.4.0-1 -> 3.4.0-2)
[2026-11-20T08:00:00+0100] [ALPM] installed htop (3.3.0-3)
";
        assert_eq!(pacman_last_upgrade(log), Some(at("2026-11-12 19:05:41")));
        assert_eq!(
            pacman_last_upgrade("[2019-03-01 10:23] [ALPM] upgraded bash (5.0.0-1 -> 5.0.002-1)\n"),
            NaiveDateTime::parse_from_str("2019-03-01 10:23", "%Y-%m-%d %H:%M").ok()
        );
        assert_eq!(pacman_last_upgrade(""), None);
    }

    #[test]
    fn rpm_install_times() {
        let mut output = String::new();
        for secs in [1_760_000_000_i64, 1_763_900_000, 1_700_000_000] {
            for _ in 0..5 {
                output.push_str(&format!("{secs}\n"));
            }
        }
        let expected = DateTime::from_timestamp(1_763_900_000, 0)
            .unwrap()
            .naive_utc();
        assert_eq!(rpm_newest_install(&output), Some(expected));
        assert_eq!(rpm_newest_install("error: rpmdb open failed\n"), None);
        assert_eq!(rpm_newest_install("1763900000\n"), None);
    }
}
