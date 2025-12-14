use std::net::IpAddr;

use clap::Parser;

/// CLI configuration for Chronos-Track
#[derive(Debug, Parser, Clone)]
#[command(
    name = "Chronos-Track",
    about = "Quartz clock skew tracker via passive TCP timestamps"
)]
pub struct Config {
    /// Network interface to capture packets from (e.g., eth0)
    #[arg(long = "interface")]
    pub interface: String,

    /// Optional IPv4/IPv6 target filter for packets
    #[arg(long = "target-ip")]
    pub target_ip: Option<IpAddr>,
}

impl Config {
    /// Parse command-line arguments into a Config
    pub fn from_args() -> Self {
        Self::parse()
    }
}
