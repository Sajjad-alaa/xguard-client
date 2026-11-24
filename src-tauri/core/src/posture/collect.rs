//! Read-only probes that collect posture facts on Linux, macOS and Windows.
//!
//! - Files are read directly where the system exposes the fact (`/proc`, `/sys`, `/etc`).
//! - The few commands that are run use absolute paths and fixed arguments: no input from the
//!   network, the server or the user ever reaches a command line. Each has a time limit and an
//!   output cap, and is killed when it overruns.
//! - Anything that cannot be determined is left unset; the server treats it as non-compliant.

use std::{process::Stdio, time::Duration};

use tokio::{io::AsyncReadExt, process::Command, time::timeout};

/// Limit for one probe command.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest output read from a probe command.
const MAX_OUTPUT: u64 = 64 * 1024;
/// Most bytes read from the end of a package log.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const MAX_LOG_TAIL: u64 = 1024 * 1024;
/// Most `/proc` entries looked at.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const MAX_PROCESSES: usize = 65_536;

/// Runs `program` with fixed `args` and returns stdout and stderr, or `None` on failure.
#[allow(dead_code)]
pub(crate) async fn run(program: &'static str, args: &'static [&'static str]) -> Option<String> {
    run_with_timeout(program, args, COMMAND_TIMEOUT).await
}

pub(crate) async fn run_with_timeout(
    program: impl AsRef<std::ffi::OsStr>,
    args: &'static [&'static str],
    limit: Duration,
) -> Option<String> {
    run_capped(program, args, limit, MAX_OUTPUT).await
}

/// Like [`run_with_timeout`] with a different output cap, for list commands (`rpm -qa`).
pub(crate) async fn run_capped(
    program: impl AsRef<std::ffi::OsStr>,
    args: &'static [&'static str],
    limit: Duration,
    max_output: u64,
) -> Option<String> {
    let program = program.as_ref();
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        // CREATE_NO_WINDOW: no console window flashes up.
        command.creation_flags(0x0800_0000);
    }
    let mut child = command.spawn().ok()?;
    let mut stdout = child.stdout.take()?;
    let mut stderr = child.stderr.take()?;
    let work = async {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let cap = max_output + 1;
        let mut out_reader = (&mut stdout).take(cap);
        let mut err_reader = (&mut stderr).take(cap);
        let (read_out, read_err) = tokio::join!(
            out_reader.read_to_end(&mut out),
            err_reader.read_to_end(&mut err),
        );
        drop((out_reader, err_reader));
        read_out.ok()?;
        read_err.ok()?;
        if out.len() as u64 > max_output || err.len() as u64 > max_output {
            drop((stdout, stderr));
            let _ = child.start_kill();
            let _ = child.wait().await;
            return None;
        }
        child.wait().await.ok()?;
        if !err.is_empty() {
            if !out.is_empty() && !out.ends_with(b"\n") {
                out.push(b'\n');
            }
            out.extend_from_slice(&err);
        }
        Some(String::from_utf8_lossy(&out).into_owned())
    };
    match timeout(limit, work).await {
        Ok(output) => output,
        Err(_) => {
            debug!("Posture probe {program:?} timed out");
            None
        }
    }
}

/// Facts collected on this platform.
#[derive(Debug, Default)]
pub(crate) struct PlatformFacts {
    pub kernel_version: Option<String>,
    pub disk_encrypted: Option<bool>,
    pub firewall_enabled: Option<bool>,
    pub screen_lock_enabled: Option<bool>,
    pub antivirus_enabled: Option<bool>,
    pub domain_joined: Option<bool>,
    pub device_integrity: Option<bool>,
    pub security_update_age_days: Option<u32>,
}

#[cfg(target_os = "linux")]
pub(crate) async fn platform_facts() -> PlatformFacts {
    use std::{
        fs,
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
    };

    use super::parse;

    fn read(path: &Path) -> Option<String> {
        use std::io::Read;
        let mut text = String::new();
        fs::File::open(path)
            .ok()?
            .take(MAX_OUTPUT)
            .read_to_string(&mut text)
            .ok()?;
        Some(text)
    }

    /// The last `MAX_LOG_TAIL` bytes of a log (newest entries are at the end), starting at a
    /// line boundary.
    fn read_tail(path: &Path) -> Option<String> {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = fs::File::open(path).ok()?;
        let len = file.metadata().ok()?.len();
        let start = len.saturating_sub(MAX_LOG_TAIL);
        file.seek(SeekFrom::Start(start)).ok()?;
        let mut bytes = Vec::new();
        file.take(MAX_LOG_TAIL).read_to_end(&mut bytes).ok()?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        Some(if start > 0 {
            text.split_once('\n')
                .map(|(_, rest)| rest.to_owned())
                .unwrap_or_default()
        } else {
            text
        })
    }

    /// Names (`comm`) of the processes owned by system accounts (uid below 1000), so a
    /// process a user starts under a well-known name does not count. `None` when `/proc`
    /// cannot be read.
    fn system_processes() -> Option<Vec<(u32, String)>> {
        let entries = fs::read_dir("/proc").ok()?;
        Some(
            entries
                .flatten()
                .filter(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .bytes()
                        .all(|b| b.is_ascii_digit())
                })
                .take(MAX_PROCESSES)
                .filter_map(|e| {
                    let uid = fs::metadata(e.path()).ok()?.uid();
                    (uid < 1000).then_some(())?;
                    let comm = fs::read_to_string(e.path().join("comm")).ok()?;
                    Some((uid, comm.trim().to_owned()))
                })
                .collect(),
        )
    }

    fn running_as_root(processes: &[(u32, String)], name: &str) -> bool {
        processes
            .iter()
            .any(|(uid, comm)| *uid == 0 && comm == name)
    }

    fn domain_joined(processes: &[(u32, String)]) -> bool {
        parse::linux_domain_joined(parse::LinuxDirectory {
            host_keytab: fs::metadata("/etc/krb5.keytab").is_ok_and(|m| m.is_file() && m.len() > 0),
            ipa_client: fs::metadata("/etc/ipa/default.conf").is_ok_and(|m| m.is_file()),
            sssd_running: running_as_root(processes, "sssd"),
            winbind_running: running_as_root(processes, "winbindd"),
        })
    }

    /// The newest package update, by package manager: apt/dpkg logs on Debian and Ubuntu (with
    /// the newest `/var/lib/dpkg/info` change when the logs were rotated since), the RPM
    /// database on Fedora, RHEL, SUSE and other RPM systems, the pacman log on Arch.
    async fn last_update() -> Option<chrono::NaiveDateTime> {
        if Path::new("/var/lib/dpkg/status").exists() {
            let apt = read_tail(Path::new("/var/log/apt/history.log"))
                .and_then(|log| parse::apt_last_upgrade(&log));
            let dpkg = read_tail(Path::new("/var/log/dpkg.log"))
                .and_then(|log| parse::dpkg_last_upgrade(&log));
            return apt.max(dpkg).or_else(newest_dpkg_change);
        }
        if Path::new("/usr/bin/rpm").exists() {
            let output = run_capped(
                "/usr/bin/rpm",
                &["-qa", "--qf", "%{INSTALLTIME}\\n"],
                COMMAND_TIMEOUT,
                1024 * 1024,
            )
            .await?;
            return parse::rpm_newest_install(&output);
        }
        read_tail(Path::new("/var/log/pacman.log")).and_then(|log| parse::pacman_last_upgrade(&log))
    }

    /// When a package was last unpacked (`/var/lib/dpkg/info/*.list` change times, local time).
    fn newest_dpkg_change() -> Option<chrono::NaiveDateTime> {
        let newest = fs::read_dir("/var/lib/dpkg/info")
            .ok()?
            .flatten()
            .take(50_000)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".list"))
            .filter_map(|e| e.metadata().ok()?.modified().ok())
            .max()?;
        Some(chrono::DateTime::<chrono::Local>::from(newest).naive_local())
    }

    fn disk_encrypted() -> Option<bool> {
        let (major, minor, source) = parse::root_mount(&read(Path::new("/proc/self/mountinfo"))?)?;
        let block = if major == 0 {
            // btrfs and similar report a virtual device; use the mount source instead.
            let device = fs::canonicalize(&source).ok()?;
            PathBuf::from("/sys/class/block").join(device.file_name()?)
        } else {
            fs::canonicalize(format!("/sys/dev/block/{major}:{minor}")).ok()?
        };
        Some(parse::is_dm_crypt(&block))
    }

    fn firewall_enabled(processes: &[(u32, String)]) -> Option<bool> {
        let ufw = read(Path::new("/etc/ufw/ufw.conf")).and_then(|conf| parse::ufw_enabled(&conf));
        let nftables = [
            "/etc/systemd/system/multi-user.target.wants/nftables.service",
            "/etc/systemd/system/sysinit.target.wants/nftables.service",
        ]
        .iter()
        .any(|path| fs::metadata(path).is_ok());
        if ufw == Some(true) || nftables || running_as_root(processes, "firewalld") {
            Some(true)
        } else {
            ufw
        }
    }

    async fn screen_lock_enabled() -> Option<bool> {
        let desktop = std::env::var("XDG_CURRENT_DESKTOP")
            .unwrap_or_default()
            .to_ascii_lowercase();
        if desktop.contains("kde") {
            let path = dirs_next::config_dir()?.join("kscreenlockerrc");
            return parse::kde_autolock(read(&path).as_deref());
        }
        let output = run(
            "/usr/bin/gsettings",
            &["get", "org.gnome.desktop.screensaver", "lock-enabled"],
        )
        .await?;
        if !parse::gsettings_bool(&output)? {
            return Some(false);
        }
        let idle = run(
            "/usr/bin/gsettings",
            &["get", "org.gnome.desktop.session", "idle-delay"],
        )
        .await?;
        parse::gnome_idle_delay_nonzero(&idle)
    }

    let processes = tokio::task::spawn_blocking(system_processes)
        .await
        .ok()
        .flatten();
    let (screen_lock_enabled, last_update) = tokio::join!(screen_lock_enabled(), last_update());
    let now = chrono::Local::now().naive_local();
    PlatformFacts {
        kernel_version: read(Path::new("/proc/sys/kernel/osrelease")).map(|v| v.trim().to_string()),
        disk_encrypted: disk_encrypted(),
        firewall_enabled: firewall_enabled(processes.as_deref().unwrap_or_default()),
        screen_lock_enabled,
        antivirus_enabled: processes.as_ref().map(|processes| {
            parse::linux_security_agent_running(processes.iter().map(|(_, comm)| comm.as_str()))
        }),
        domain_joined: processes.as_deref().map(domain_joined),
        security_update_age_days: last_update.and_then(|then| parse::age_days(then, now)),
        ..Default::default()
    }
}

#[cfg(target_os = "macos")]
pub(crate) async fn platform_facts() -> PlatformFacts {
    use super::parse;

    /// Readable by everyone; can grow over the years, so it is capped.
    const INSTALL_HISTORY: &str = "/Library/Receipts/InstallHistory.plist";
    const MAX_INSTALL_HISTORY: u64 = 32 * 1024 * 1024;

    fn last_os_update() -> Option<chrono::NaiveDateTime> {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(INSTALL_HISTORY)
            .ok()?
            .take(MAX_INSTALL_HISTORY + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() as u64 > MAX_INSTALL_HISTORY {
            return None;
        }
        parse::macos_last_os_update(&bytes)
    }

    let (filevault, firewall, screen_lock, sip, processes, ad, ldap, last_update) = tokio::join!(
        run("/usr/bin/fdesetup", &["status"]),
        run(
            "/usr/libexec/ApplicationFirewall/socketfilterfw",
            &["--getglobalstate"]
        ),
        run("/usr/sbin/sysadminctl", &["-screenLock", "status"]),
        run("/usr/bin/csrutil", &["status"]),
        run_capped(
            "/bin/ps",
            &["-axo", "uid=,comm="],
            COMMAND_TIMEOUT,
            1024 * 1024
        ),
        run("/usr/sbin/dsconfigad", &["-show"]),
        run("/usr/bin/dscl", &["localhost", "-list", "/LDAPv3"]),
        async {
            tokio::task::spawn_blocking(last_os_update)
                .await
                .ok()
                .flatten()
        },
    );
    let now = chrono::Utc::now().naive_utc();
    PlatformFacts {
        kernel_version: None,
        disk_encrypted: filevault.as_deref().and_then(parse::filevault_on),
        firewall_enabled: firewall.as_deref().and_then(parse::macos_firewall_enabled),
        screen_lock_enabled: screen_lock.as_deref().and_then(parse::macos_screen_lock),
        device_integrity: sip.as_deref().and_then(parse::sip_enabled),
        antivirus_enabled: processes
            .as_deref()
            .and_then(parse::macos_security_agent_running),
        domain_joined: parse::macos_domain_joined(
            ad.as_deref().and_then(parse::macos_ad_bound),
            ldap.as_deref().and_then(parse::macos_ldap_bound),
        ),
        security_update_age_days: last_update.and_then(|then| parse::age_days(then, now)),
    }
}

/// Read-only PowerShell probe. Prints `key=value` lines; see `parse::windows_report`.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const WINDOWS_SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$drive = $env:SystemDrive
if ($drive -notmatch '^[A-Za-z]:$') { $drive = 'C:' }
$b = (New-Object -ComObject Shell.Application).NameSpace($drive + '\').Self.ExtendedProperty('System.Volume.BitLockerProtection')
"bitlocker=$b"
$local = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
$policy = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
foreach ($p in @(@('domain','DomainProfile','DomainProfile'), @('private','StandardProfile','PrivateProfile'), @('public','PublicProfile','PublicProfile'))) {
  "fw_$($p[0])=$((Get-ItemProperty "$local\$($p[1])").EnableFirewall)"
  "fw_policy_$($p[0])=$((Get-ItemProperty "$policy\$($p[2])").EnableFirewall)"
}
$desk = Get-ItemProperty 'HKCU:\Control Panel\Desktop'
"saver_active=$($desk.ScreenSaveActive)"
"saver_secure=$($desk.ScreenSaverIsSecure)"
$pdesk = Get-ItemProperty 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
"saver_policy_active=$($pdesk.ScreenSaveActive)"
"saver_policy_secure=$($pdesk.ScreenSaverIsSecure)"
"inactivity_timeout=$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').InactivityTimeoutSecs)"
"av_states=$((Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct).productState -join ',')"
"domain_joined=$((Get-CimInstance Win32_ComputerSystem).PartOfDomain)"
$h = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($h) { "update_age_days=$([int]((Get-Date) - $h.InstalledOn).TotalDays)" }
"#;

#[cfg(windows)]
pub(crate) async fn platform_facts() -> PlatformFacts {
    use std::path::PathBuf;

    use super::parse;

    let system_root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    let powershell =
        PathBuf::from(system_root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    static ARGS: [&str; 6] = [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        WINDOWS_SCRIPT,
    ];
    let report = run_with_timeout(&powershell, &ARGS, Duration::from_secs(15))
        .await
        .unwrap_or_default();
    let report = parse::windows_report(&report);
    PlatformFacts {
        kernel_version: None,
        disk_encrypted: report.disk_encrypted,
        firewall_enabled: report.firewall_enabled,
        screen_lock_enabled: report.screen_lock_enabled,
        antivirus_enabled: report.antivirus_enabled,
        domain_joined: report.domain_joined,
        device_integrity: None,
        security_update_age_days: report.security_update_age_days,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(crate) async fn platform_facts() -> PlatformFacts {
    PlatformFacts::default()
}
