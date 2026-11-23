//! Provisioning files: let an administrator (or an MDM tool) pre-configure enrollment.
//!
//! An XGuard administrator creates a provisioning file for a user (**Users → user menu →
//! Download client provisioning file**). Deployed as `provisioning.json` to one of the paths
//! below, it makes a client without instances start the enrollment with its Edge URL and token.
//!
//! | Scope | Path | Required permissions |
//! |---|---|---|
//! | system (MDM) | Linux `/etc/xguard/provisioning.json` | owned by root, not writable by group or others, in a root-owned directory not writable by group or others |
//! | system (MDM) | macOS `/Library/Application Support/XGuard/provisioning.json` | same as Linux |
//! | system (MDM) | Windows `provisioning.json` next to `xguard-client.exe`, only when installed under `%ProgramFiles%` | inherits the install directory's administrator-only write access |
//! | user | `<app data dir>/provisioning.json` | owned by the user, no access for group or others (Unix), not a link |
//!
//! System files are checked first. The file holds a short-lived single-use enrollment token, so
//! a leaked file stops working once used or expired. A token already used on this machine is
//! remembered and not offered again; a user file is deleted after its enrollment succeeds.

use std::{
    fmt, fs,
    io::Read,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use reqwest::Url;
use serde::{Deserialize, Serialize};

pub const PROVISIONING_FILE_NAME: &str = "provisioning.json";
/// Tokens already enrolled with on this machine.
const CONSUMED_FILE_NAME: &str = "provisioning.consumed";
/// Upper bound on a provisioning file.
pub const MAX_FILE_SIZE: u64 = 16 * 1024;
const MAX_TOKEN_LENGTH: usize = 256;
const MAX_URL_LENGTH: usize = 2048;

/// What the app needs to start the enrollment. Matches the UI's `ProvisioningConfig` type.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProvisioningConfig {
    pub enrollment_url: String,
    pub enrollment_token: String,
}

impl fmt::Debug for ProvisioningConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProvisioningConfig")
            .field("enrollment_url", &self.enrollment_url)
            .field("enrollment_token", &"***")
            .finish()
    }
}

/// The file format. Version 1 is written by XGuard; files without a version (Defguard's
/// `{enrollment_url, enrollment_token}`) are read too.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisioningFile {
    #[serde(default)]
    version: Option<u32>,
    enrollment_url: String,
    enrollment_token: String,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    instance_name: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    username: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Deployed by an administrator for the whole machine.
    System,
    /// In the user's own app data directory.
    User,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProvisioningError {
    #[error("no provisioning file")]
    NotFound,
    #[error("the file is larger than {MAX_FILE_SIZE} bytes")]
    TooLarge,
    #[error("unsafe file: {0}")]
    Insecure(String),
    #[error("cannot read the file: {0}")]
    Unreadable(String),
    #[error("invalid provisioning file: {0}")]
    Invalid(String),
    #[error("the enrollment token has expired")]
    Expired,
    #[error("the enrollment token was already used on this computer")]
    Consumed,
}

fn valid_url(raw: &str) -> Result<(), ProvisioningError> {
    if raw.len() > MAX_URL_LENGTH {
        return Err(ProvisioningError::Invalid("enrollment_url too long".into()));
    }
    let url = Url::parse(raw)
        .map_err(|_| ProvisioningError::Invalid("enrollment_url is not a URL".into()))?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if !(url.scheme() == "https" || (url.scheme() == "http" && loopback)) {
        return Err(ProvisioningError::Invalid(
            "enrollment_url must use https".into(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ProvisioningError::Invalid(
            "enrollment_url must not contain credentials".into(),
        ));
    }
    Ok(())
}

/// Parses and validates a provisioning file's contents.
pub fn parse_provisioning(
    content: &str,
    now: DateTime<Utc>,
) -> Result<ProvisioningConfig, ProvisioningError> {
    let content = content.trim_start_matches('\u{FEFF}');
    let file: ProvisioningFile =
        serde_json::from_str(content).map_err(|err| ProvisioningError::Invalid(err.to_string()))?;
    if let Some(version) = file.version {
        if version != 1 {
            return Err(ProvisioningError::Invalid(format!(
                "unsupported version {version}"
            )));
        }
    }
    valid_url(&file.enrollment_url)?;
    let token = file.enrollment_token.trim();
    if token.is_empty()
        || token.len() > MAX_TOKEN_LENGTH
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(ProvisioningError::Invalid(
            "enrollment_token is malformed".into(),
        ));
    }
    if let Some(expires_at) = file.expires_at {
        let expires_at = DateTime::parse_from_rfc3339(&expires_at)
            .map_err(|_| ProvisioningError::Invalid("expires_at is not RFC 3339".into()))?;
        if expires_at <= now {
            return Err(ProvisioningError::Expired);
        }
    }
    Ok(ProvisioningConfig {
        enrollment_url: file.enrollment_url,
        enrollment_token: token.to_owned(),
    })
}

fn check_file_metadata(
    metadata: &fs::Metadata,
    parent_meta: &fs::Metadata,
    scope: Scope,
) -> Result<(), ProvisioningError> {
    if !metadata.file_type().is_file() {
        return Err(ProvisioningError::Insecure(
            "not a regular file (links are not followed)".into(),
        ));
    }
    if metadata.len() > MAX_FILE_SIZE {
        return Err(ProvisioningError::TooLarge);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if !parent_meta.file_type().is_dir() {
            return Err(ProvisioningError::Insecure(
                "parent directory is not a real directory".into(),
            ));
        }
        let mode = metadata.permissions().mode();
        match scope {
            Scope::User => {
                let uid = nix::unistd::geteuid().as_raw();
                if metadata.uid() != uid {
                    return Err(ProvisioningError::Insecure("owned by another user".into()));
                }
                if mode & 0o077 != 0 {
                    return Err(ProvisioningError::Insecure(format!(
                        "mode {:o} lets group or others access it; use 600",
                        mode & 0o777
                    )));
                }
            }
            Scope::System => {
                if metadata.uid() != 0 {
                    return Err(ProvisioningError::Insecure("not owned by root".into()));
                }
                if mode & 0o022 != 0 {
                    return Err(ProvisioningError::Insecure(format!(
                        "mode {:o} lets group or others write it",
                        mode & 0o777
                    )));
                }
                if parent_meta.uid() != 0 || parent_meta.permissions().mode() & 0o022 != 0 {
                    return Err(ProvisioningError::Insecure(
                        "its directory is not root-owned or is writable by others".into(),
                    ));
                }
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (parent_meta, scope);
    Ok(())
}

/// Checks that only the right account can have written the file (and, for user files, that
/// nobody else can read it).
#[cfg(unix)]
pub fn check_permissions(path: &Path, scope: Scope) -> Result<(), ProvisioningError> {
    let metadata = fs::symlink_metadata(path).map_err(|err| match err.kind() {
        std::io::ErrorKind::NotFound => ProvisioningError::NotFound,
        _ => ProvisioningError::Unreadable(err.to_string()),
    })?;
    let parent = path
        .parent()
        .ok_or_else(|| ProvisioningError::Insecure("no parent directory".into()))?;
    let parent_meta = fs::symlink_metadata(parent)
        .map_err(|err| ProvisioningError::Unreadable(err.to_string()))?;
    check_file_metadata(&metadata, &parent_meta, scope)
}

/// Windows: refuses links and oversized files. Write access is governed by the directory's ACL
/// (system files are only looked for under `%ProgramFiles%`, user files in the user's profile).
#[cfg(windows)]
pub fn check_permissions(path: &Path, scope: Scope) -> Result<(), ProvisioningError> {
    let metadata = fs::symlink_metadata(path).map_err(|err| match err.kind() {
        std::io::ErrorKind::NotFound => ProvisioningError::NotFound,
        _ => ProvisioningError::Unreadable(err.to_string()),
    })?;
    let parent = path
        .parent()
        .ok_or_else(|| ProvisioningError::Insecure("no parent directory".into()))?;
    let parent_meta = fs::symlink_metadata(parent)
        .map_err(|err| ProvisioningError::Unreadable(err.to_string()))?;
    check_file_metadata(&metadata, &parent_meta, scope)
}

/// Reads and validates the file at `path`.
pub fn read_provisioning(
    path: &Path,
    scope: Scope,
    now: DateTime<Utc>,
) -> Result<ProvisioningConfig, ProvisioningError> {
    let parent = path
        .parent()
        .ok_or_else(|| ProvisioningError::Insecure("no parent directory".into()))?;
    let parent_meta = fs::symlink_metadata(parent).map_err(|err| match err.kind() {
        std::io::ErrorKind::NotFound => ProvisioningError::NotFound,
        _ => ProvisioningError::Unreadable(err.to_string()),
    })?;
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;

        let sym_meta = fs::symlink_metadata(path).map_err(|err| match err.kind() {
            std::io::ErrorKind::NotFound => ProvisioningError::NotFound,
            _ => ProvisioningError::Unreadable(err.to_string()),
        })?;
        if !sym_meta.file_type().is_file() {
            return Err(ProvisioningError::Insecure(
                "not a regular file (links are not followed)".into(),
            ));
        }
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)
            .map_err(|err| match err.kind() {
                std::io::ErrorKind::NotFound => ProvisioningError::NotFound,
                _ if err.raw_os_error() == Some(nix::libc::ELOOP) => ProvisioningError::Insecure(
                    "not a regular file (links are not followed)".into(),
                ),
                _ => ProvisioningError::Unreadable(err.to_string()),
            })?
    };
    #[cfg(not(unix))]
    let file = {
        check_permissions(path, scope)?;
        fs::File::open(path).map_err(|err| ProvisioningError::Unreadable(err.to_string()))?
    };
    let metadata = file
        .metadata()
        .map_err(|err| ProvisioningError::Unreadable(err.to_string()))?;
    check_file_metadata(&metadata, &parent_meta, scope)?;
    let mut content = String::new();
    file.take(MAX_FILE_SIZE + 1)
        .read_to_string(&mut content)
        .map_err(|err| ProvisioningError::Unreadable(err.to_string()))?;
    if content.len() as u64 > MAX_FILE_SIZE {
        return Err(ProvisioningError::TooLarge);
    }
    parse_provisioning(&content, now)
}

/// The machine-wide path for this platform, if any.
#[must_use]
pub fn system_path() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        Some(PathBuf::from("/etc/xguard").join(PROVISIONING_FILE_NAME))
    }
    #[cfg(target_os = "macos")]
    {
        Some(PathBuf::from("/Library/Application Support/XGuard").join(PROVISIONING_FILE_NAME))
    }
    #[cfg(windows)]
    {
        // Only an installation under Program Files: elsewhere the directory may be user-writable.
        let exe = std::env::current_exe().ok()?;
        let dir = exe.parent()?;
        let program_files = std::env::var_os("ProgramFiles").map(PathBuf::from)?;
        let pf_parts: Vec<_> = program_files.components().collect();
        let dir_parts: Vec<_> = dir.components().collect();
        let under_program_files = !pf_parts.is_empty()
            && dir_parts.len() >= pf_parts.len()
            && pf_parts.iter().zip(&dir_parts).all(|(a, b)| {
                a.as_os_str()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&b.as_os_str().to_string_lossy())
            });
        under_program_files.then(|| dir.join(PROVISIONING_FILE_NAME))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        None
    }
}

/// Paths to look at, in order.
#[must_use]
pub fn candidates(app_data_dir: &Path) -> Vec<(PathBuf, Scope)> {
    let mut paths = Vec::new();
    if let Some(path) = system_path() {
        paths.push((path, Scope::System));
    }
    paths.push((app_data_dir.join(PROVISIONING_FILE_NAME), Scope::User));
    paths
}

fn consumed_tokens(app_data_dir: &Path) -> Vec<String> {
    fs::read_to_string(app_data_dir.join(CONSUMED_FILE_NAME))
        .map(|content| content.lines().map(str::to_owned).collect())
        .unwrap_or_default()
}

/// A provisioning file found on this machine.
#[derive(Debug, Clone)]
pub struct FoundProvisioning {
    pub config: ProvisioningConfig,
    pub path: PathBuf,
    pub scope: Scope,
}

/// Looks for a usable provisioning file. Problems are logged, never fatal.
#[must_use]
pub fn find_provisioning(app_data_dir: &Path, now: DateTime<Utc>) -> Option<FoundProvisioning> {
    let consumed = consumed_tokens(app_data_dir);
    for (path, scope) in candidates(app_data_dir) {
        match read_provisioning(&path, scope, now) {
            Ok(config) if consumed.contains(&config.enrollment_token) => {
                debug!(
                    "Ignoring provisioning file {}: {}",
                    path.display(),
                    ProvisioningError::Consumed
                );
            }
            Ok(config) => {
                info!("Using provisioning file {}", path.display());
                return Some(FoundProvisioning {
                    config,
                    path,
                    scope,
                });
            }
            Err(ProvisioningError::NotFound) => {}
            Err(err) => warn!("Ignoring provisioning file {}: {err}", path.display()),
        }
    }
    None
}

/// Records that the token was used, and deletes a user-scoped file.
pub fn mark_consumed(app_data_dir: &Path, found: &FoundProvisioning) {
    let mut consumed = consumed_tokens(app_data_dir);
    if !consumed.contains(&found.config.enrollment_token) {
        consumed.push(found.config.enrollment_token.clone());
        // Keep the list short: old tokens are long expired.
        let start = consumed.len().saturating_sub(16);
        let payload = consumed[start..].join("\n");
        let path = app_data_dir.join(CONSUMED_FILE_NAME);
        let tmp = app_data_dir.join(format!("{CONSUMED_FILE_NAME}.tmp.{}", std::process::id()));
        let _ = fs::remove_file(&tmp);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let write_result = options.open(&tmp).and_then(|mut file| {
            use std::io::Write;
            file.write_all(payload.as_bytes())?;
            file.flush()?;
            file.sync_all()?;
            drop(file);
            fs::rename(&tmp, &path)
        });
        if let Err(err) = write_result {
            let _ = fs::remove_file(&tmp);
            warn!("Failed to record the used provisioning token: {err}");
        }
    }
    if found.scope == Scope::User {
        match fs::remove_file(&found.path) {
            Ok(()) => debug!("Removed provisioning file {}", found.path.display()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => warn!(
                "Failed to remove provisioning file {}: {err}",
                found.path.display()
            ),
        }
    }
}

#[cfg(test)]
mod tests;
