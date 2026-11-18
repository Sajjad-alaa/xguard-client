//! Validated, root-only storage of service locations: one JSON file per instance.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use xguard_client_proto::xguard::client::v1::{
    SaveServiceLocationsRequest, ServiceLocationMode as ProtoMode,
};
use xguard_wireguard_rs::{key::Key, net::IpAddrMask};

/// Format version of the stored files.
pub const SCHEMA_VERSION: u32 = 1;
/// Limits keeping one misbehaving caller from filling the disk or the routing table.
pub const MAX_LOCATIONS_PER_INSTANCE: usize = 32;
pub const MAX_INSTANCES: usize = 16;
const MAX_FILE_SIZE: u64 = 256 * 1024;
const MAX_NAME_LENGTH: usize = 128;
const MAX_LIST_LENGTH: usize = 4096;
const MAX_HOST_LENGTH: usize = 253;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StoreError {
    #[error("invalid {field}: {reason}")]
    Invalid { field: &'static str, reason: String },
    #[error("too many service locations (at most {MAX_LOCATIONS_PER_INSTANCE} per instance)")]
    TooManyLocations,
    #[error("too many instances with service locations (at most {MAX_INSTANCES})")]
    TooManyInstances,
    #[error("storage error: {0}")]
    Io(String),
}

impl From<std::io::Error> for StoreError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

fn invalid(field: &'static str, reason: impl Into<String>) -> StoreError {
    StoreError::Invalid {
        field,
        reason: reason.into(),
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Up only while no user is signed in.
    PreLogon,
    /// Always up.
    AlwaysOn,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct StoredLocation {
    pub network_id: i64,
    pub name: String,
    pub address: String,
    pub pubkey: String,
    pub endpoint: String,
    pub allowed_ips: String,
    pub dns: Option<String>,
    pub keepalive_interval: u16,
    pub mtu: Option<u32>,
    pub mode: Mode,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct StoredInstance {
    pub schema_version: u32,
    pub instance_id: String,
    pub private_key: String,
    pub locations: Vec<StoredLocation>,
}

impl std::fmt::Debug for StoredInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredInstance")
            .field("instance_id", &self.instance_id)
            .field("private_key", &"***")
            .field("locations", &self.locations)
            .finish()
    }
}

/// A UUID in canonical lowercase form (it names the file, so nothing else is accepted).
pub fn validate_instance_id(id: &str) -> Result<String, StoreError> {
    let id = id.trim().to_ascii_lowercase();
    let valid = id.len() == 36
        && id.char_indices().all(|(index, c)| match index {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        });
    if valid {
        Ok(id)
    } else {
        Err(invalid("instance_id", "not a UUID"))
    }
}

fn validate_key(field: &'static str, key: &str) -> Result<(), StoreError> {
    Key::from_str(key.trim())
        .map(|_| ())
        .map_err(|_| invalid(field, "not a WireGuard key"))
}

fn validate_name(name: &str) -> Result<String, StoreError> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > MAX_NAME_LENGTH
        || name.chars().any(char::is_control)
    {
        return Err(invalid(
            "name",
            "empty, too long or contains control characters",
        ));
    }
    Ok(name.to_owned())
}

fn validate_addresses(field: &'static str, list: &str) -> Result<String, StoreError> {
    if list.len() > MAX_LIST_LENGTH {
        return Err(invalid(field, "too long"));
    }
    let parsed: Vec<String> = list
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            IpAddrMask::from_str(entry)
                .map(|_| entry.to_owned())
                .map_err(|_| invalid(field, format!("{entry:?} is not an address")))
        })
        .collect::<Result<_, _>>()?;
    if parsed.is_empty() {
        return Err(invalid(field, "empty"));
    }
    Ok(parsed.join(","))
}

/// `host:port` or `[v6]:port`, syntax only: the host is resolved when the tunnel comes up.
pub fn validate_endpoint(endpoint: &str) -> Result<String, StoreError> {
    let endpoint = endpoint.trim();
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| invalid("endpoint", "missing port"))?;
    port.parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| invalid("endpoint", "bad port"))?;
    let host_ok = if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        v6.parse::<std::net::Ipv6Addr>().is_ok()
    } else {
        !host.is_empty()
            && host.len() <= MAX_HOST_LENGTH
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    };
    if !host_ok {
        return Err(invalid("endpoint", "bad host"));
    }
    Ok(endpoint.to_owned())
}

fn validate_dns(dns: &str) -> Result<Option<String>, StoreError> {
    let dns = dns.trim();
    if dns.is_empty() {
        return Ok(None);
    }
    if dns.len() > MAX_LIST_LENGTH
        || !dns
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".:-,_ []".contains(&b))
    {
        return Err(invalid("dns", "unexpected characters"));
    }
    Ok(Some(dns.to_owned()))
}

impl StoredInstance {
    /// Validates and canonicalizes a save request from the app.
    pub fn from_request(request: &SaveServiceLocationsRequest) -> Result<Self, StoreError> {
        let instance_id = validate_instance_id(&request.instance_id)?;
        validate_key("private_key", &request.private_key)?;
        if request.service_locations.len() > MAX_LOCATIONS_PER_INSTANCE {
            return Err(StoreError::TooManyLocations);
        }
        let mut locations = Vec::with_capacity(request.service_locations.len());
        for location in &request.service_locations {
            validate_key("pubkey", &location.pubkey)?;
            let mode = match ProtoMode::try_from(location.mode) {
                Ok(ProtoMode::PreLogon) => Mode::PreLogon,
                Ok(ProtoMode::AlwaysOn) => Mode::AlwaysOn,
                Err(_) => return Err(invalid("mode", "unknown")),
            };
            if location.posture_check_required {
                return Err(invalid(
                    "posture_check_required",
                    "service locations cannot use posture checks",
                ));
            }
            locations.push(StoredLocation {
                network_id: location.core_location_id,
                name: validate_name(&location.name)?,
                address: validate_addresses("address", &location.address)?,
                pubkey: location.pubkey.trim().to_owned(),
                endpoint: validate_endpoint(&location.endpoint)?,
                allowed_ips: validate_addresses("allowed_ips", &location.allowed_ips)?,
                dns: validate_dns(&location.dns)?,
                keepalive_interval: u16::try_from(location.keepalive_interval.min(3600))
                    .unwrap_or(25),
                mtu: location.mtu.filter(|mtu| (576..=9200).contains(mtu)),
                mode,
            });
        }
        locations.sort_by_key(|location| location.network_id);
        locations.dedup_by_key(|location| location.network_id);
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            instance_id,
            private_key: request.private_key.trim().to_owned(),
            locations,
        })
    }

    /// Re-checks a file read from disk.
    fn validate_loaded(&self) -> Result<(), StoreError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(invalid("schema_version", "unsupported"));
        }
        validate_instance_id(&self.instance_id)?;
        validate_key("private_key", &self.private_key)?;
        if self.locations.len() > MAX_LOCATIONS_PER_INSTANCE {
            return Err(StoreError::TooManyLocations);
        }
        for location in &self.locations {
            validate_key("pubkey", &location.pubkey)?;
            validate_name(&location.name)?;
            validate_addresses("address", &location.address)?;
            validate_addresses("allowed_ips", &location.allowed_ips)?;
            validate_endpoint(&location.endpoint)?;
            if let Some(dns) = &location.dns {
                validate_dns(dns)?;
            }
        }
        Ok(())
    }
}

/// One directory, readable only by the service account.
#[derive(Clone, Debug)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Default location: `/etc/xguard/service_locations` on Unix; on Windows the service
    /// account's local app data (`SYSTEM` profile), which users cannot read.
    #[must_use]
    pub fn default_dir() -> PathBuf {
        #[cfg(windows)]
        {
            std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    PathBuf::from(r"C:\Windows\System32\config\systemprofile\AppData\Local")
                })
                .join("XGuard")
                .join("service_locations")
        }
        #[cfg(not(windows))]
        {
            PathBuf::from("/etc/xguard/service_locations")
        }
    }

    fn ensure_dir(&self) -> Result<(), StoreError> {
        fs::create_dir_all(&self.dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    fn path(&self, instance_id: &str) -> Result<PathBuf, StoreError> {
        Ok(self
            .dir
            .join(format!("{}.json", validate_instance_id(instance_id)?)))
    }

    /// Saves an instance's locations; an empty list removes the file. Returns whether anything
    /// changed on disk.
    pub fn save(&self, instance: &StoredInstance) -> Result<bool, StoreError> {
        if instance.locations.is_empty() {
            return self.delete(&instance.instance_id);
        }
        let path = self.path(&instance.instance_id)?;
        let json = serde_json::to_string_pretty(instance)
            .map_err(|err| StoreError::Io(err.to_string()))?;
        if fs::read_to_string(&path).is_ok_and(|existing| existing == json) {
            return Ok(false);
        }
        self.ensure_dir()?;
        if !path.exists() && self.instance_files()?.len() >= MAX_INSTANCES {
            return Err(StoreError::TooManyInstances);
        }
        // Write a private temporary file, then rename over the old one: readers never see a
        // partial file and the secret is never world-readable, even briefly.
        let tmp = path.with_extension("json.tmp");
        let _ = fs::remove_file(&tmp);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, &path)?;
        Ok(true)
    }

    /// Removes an instance's locations. Returns whether a file was removed.
    pub fn delete(&self, instance_id: &str) -> Result<bool, StoreError> {
        match fs::remove_file(self.path(instance_id)?) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(err.into()),
        }
    }

    fn instance_files(&self) -> Result<Vec<PathBuf>, StoreError> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err.into()),
        };
        let mut files: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension().is_some_and(|ext| ext == "json")
                    && path
                        .file_stem()
                        .and_then(|stem| stem.to_str())
                        .is_some_and(|stem| validate_instance_id(stem).is_ok())
            })
            .collect();
        files.sort();
        Ok(files)
    }

    /// Everything stored. Files that are unreadable, oversized, links or invalid are skipped.
    pub fn load_all(&self) -> Vec<StoredInstance> {
        let files = match self.instance_files() {
            Ok(files) => files,
            Err(err) => {
                tracing::error!("Failed to list service locations: {err}");
                return Vec::new();
            }
        };
        files
            .into_iter()
            .take(MAX_INSTANCES)
            .filter_map(|path| match load_file(&path) {
                Ok(instance) => Some(instance),
                Err(err) => {
                    tracing::warn!("Ignoring service location file {}: {err}", path.display());
                    None
                }
            })
            .collect()
    }
}

fn load_file(path: &Path) -> Result<StoredInstance, StoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(StoreError::Io("not a regular file".into()));
    }
    if metadata.len() > MAX_FILE_SIZE {
        return Err(StoreError::Io("file too large".into()));
    }
    let instance: StoredInstance = serde_json::from_str(&fs::read_to_string(path)?)
        .map_err(|err| StoreError::Io(err.to_string()))?;
    instance.validate_loaded()?;
    let expected = path.file_stem().and_then(|stem| stem.to_str());
    if expected != Some(instance.instance_id.as_str()) {
        return Err(invalid("instance_id", "does not match the file name"));
    }
    Ok(instance)
}
