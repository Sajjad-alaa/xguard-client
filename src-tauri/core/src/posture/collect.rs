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
        let cap = MAX_OUTPUT + 1;
        let mut out_reader = (&mut stdout).take(cap);
        let mut err_reader = (&mut stderr).take(cap);
        let (read_out, read_err) = tokio::join!(
            out_reader.read_to_end(&mut out),
            err_reader.read_to_end(&mut err),
        );
        drop((out_reader, err_reader));
        read_out.ok()?;
        read_err.ok()?;
        if out.len() as u64 > MAX_OUTPUT || err.len() as u64 > MAX_OUTPUT {
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

    fn firewalld_running() -> bool {
        let Ok(entries) = fs::read_dir("/proc") else {
            return false;
        };
        entries.flatten().any(|e| {
            e.file_name()
                .to_string_lossy()
                .bytes()
                .all(|b| b.is_ascii_digit())
                && fs::metadata(e.path()).is_ok_and(|meta| meta.uid() == 0)
                && fs::read_to_string(e.path().join("comm"))
                    .is_ok_and(|comm| comm.trim() == "firewalld")
        })
    }

    fn firewall_enabled() -> Option<bool> {
        let ufw = read(Path::new("/etc/ufw/ufw.conf")).and_then(|conf| parse::ufw_enabled(&conf));
        let nftables = [
            "/etc/systemd/system/multi-user.target.wants/nftables.service",
            "/etc/systemd/system/sysinit.target.wants/nftables.service",
        ]
        .iter()
        .any(|path| fs::metadata(path).is_ok());
        if ufw == Some(true) || nftables || firewalld_running() {
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

    PlatformFacts {
        kernel_version: read(Path::new("/proc/sys/kernel/osrelease")).map(|v| v.trim().to_string()),
        disk_encrypted: disk_encrypted(),
        firewall_enabled: firewall_enabled(),
        screen_lock_enabled: screen_lock_enabled().await,
        ..Default::default()
    }
}

#[cfg(target_os = "macos")]
pub(crate) async fn platform_facts() -> PlatformFacts {
    use super::parse;

    let (filevault, firewall, screen_lock, sip) = tokio::join!(
        run("/usr/bin/fdesetup", &["status"]),
        run(
            "/usr/libexec/ApplicationFirewall/socketfilterfw",
            &["--getglobalstate"]
        ),
        run("/usr/sbin/sysadminctl", &["-screenLock", "status"]),
        run("/usr/bin/csrutil", &["status"]),
    );
    PlatformFacts {
        kernel_version: None,
        disk_encrypted: filevault.as_deref().and_then(parse::filevault_on),
        firewall_enabled: firewall.as_deref().and_then(parse::macos_firewall_enabled),
        screen_lock_enabled: screen_lock.as_deref().and_then(parse::macos_screen_lock),
        device_integrity: sip.as_deref().and_then(parse::sip_enabled),
        ..Default::default()
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
