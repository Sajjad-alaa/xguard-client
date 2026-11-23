use clap::Parser;

fn default_log_dir() -> String {
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .map(|p| p.join("XGuard").join("logs"))
            .unwrap_or_else(|| {
                std::path::PathBuf::from(
                    r"C:\Windows\System32\config\systemprofile\AppData\Local\XGuard\logs",
                )
            })
            .to_string_lossy()
            .into_owned()
    }
    #[cfg(not(windows))]
    {
        "/var/log/xguard-service".to_owned()
    }
}

#[derive(Debug, Parser, Clone)]
#[clap(about = "XGuard VPN client interface management service")]
#[command(name = "xguard-service", version)]
pub struct Config {
    /// Configures log level of xguard service logs
    #[arg(long, env = "XGUARD_LOG_LEVEL", default_value = "info")]
    pub log_level: String,

    /// Configures logging directory; it is meant for debugging only, so hide it.
    #[arg(long, env = "XGUARD_LOG_DIR", default_value_t = default_log_dir(), hide = true)]
    pub log_dir: String,

    /// Configures maximum number of service log files to keep. Set to 0 to disable cleanup.
    #[arg(long, env = "XGUARD_LOG_MAX_FILES", default_value_t = 8)]
    pub log_max_files: usize,

    /// Defines how often (in seconds) interface statistics are sent to xguard client
    #[arg(long, short = 'p', env = "XGUARD_STATS_PERIOD", default_value = "10")]
    pub stats_period: u64,
}
