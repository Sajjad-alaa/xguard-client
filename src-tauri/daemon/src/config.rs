use clap::Parser;

#[cfg(windows)]
pub const DEFAULT_LOG_DIR: &str = "/Logs/xguard-service";
#[cfg(not(windows))]
pub const DEFAULT_LOG_DIR: &str = "/var/log/xguard-service";

#[derive(Debug, Parser, Clone)]
#[clap(about = "XGuard VPN client interface management service")]
#[command(name = "xguard-service", version)]
pub struct Config {
    /// Configures log level of xguard service logs
    #[arg(long, env = "XGUARD_LOG_LEVEL", default_value = "info")]
    pub log_level: String,

    /// Configures logging directory; it is meant for debugging only, so hide it.
    #[arg(long, env = "XGUARD_LOG_DIR", default_value = DEFAULT_LOG_DIR, hide = true)]
    pub log_dir: String,

    /// Configures maximum number of service log files to keep. Set to 0 to disable cleanup.
    #[arg(long, env = "XGUARD_LOG_MAX_FILES", default_value_t = 8)]
    pub log_max_files: usize,

    /// Defines how often (in seconds) interface statistics are sent to xguard client
    #[arg(long, short = 'p', env = "XGUARD_STATS_PERIOD", default_value = "10")]
    pub stats_period: u64,
}
