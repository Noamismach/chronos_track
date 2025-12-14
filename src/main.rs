mod analysis;
mod config;
mod injector;
mod sniffer;

use std::error::Error;
use std::fs::File;
use std::io::{self, BufWriter};
use std::process;
use std::thread;

use analysis::{Point, calculate_skew, compute_lower_hull, slope_to_ppm};
use config::Config;
use std::net::{IpAddr, Ipv4Addr};

const ANALYSIS_INTERVAL: u64 = 50;
const NS_PER_SEC: f64 = 1_000_000_000.0;
const SOURCE_PORT: u16 = 54_321;
const TARGET_PORT: u16 = 80;

fn main() {
    env_logger::init();

    if let Err(err) = run() {
        log::error!("Chronos-Track terminated: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let cfg = Config::from_args();
    let target_filter = cfg.target_ip;
    let injection_target = resolve_target_v4(target_filter)?;

    log::info!(
        "Chronos-Track starting on interface {} (target={:?})",
        cfg.interface,
        target_filter
    );

    let _rst_guard = RstGuard::install(SOURCE_PORT)?;

    ctrlc::set_handler({
        let port = SOURCE_PORT;
        move || {
            injector::cleanup_rst(port);
            process::exit(0);
        }
    })?;

    thread::spawn(move || {
        injector::start_injection_loop(injection_target, TARGET_PORT, SOURCE_PORT);
    });

    let file = File::create("measurements.csv")?;
    let mut csv_writer = csv::Writer::from_writer(BufWriter::new(file));
    csv_writer.write_record(["kernel_time_ns", "sender_ts_val", "src_ip"])?;

    let socket = match sniffer::create_precision_socket(&cfg.interface) {
        Ok(sock) => sock,
        Err(err) => {
            if err.kind() == io::ErrorKind::PermissionDenied {
                log::error!(
                    "Permission denied opening raw socket on '{}'. Run as root or grant CAP_NET_RAW.",
                    cfg.interface
                );
            }
            return Err(Box::new(err));
        }
    };

    let mut points: Vec<Point> = Vec::new();
    let mut packet_counter: u64 = 0;

    loop {
        let sample = match sniffer::recv_packet(&socket) {
            Ok(Some(sample)) => sample,
            Ok(None) => continue,
            Err(err) => {
                log::warn!("recv_packet failed: {err}");
                continue;
            }
        };

        if let Some(filter_ip) = target_filter {
            if sample.src_ip != filter_ip {
                continue;
            }
        }

        let point = Point::new(
            sample.sender_ts_val as f64,
            sample.kernel_time_ns as f64 / NS_PER_SEC,
        );
        points.push(point);
        packet_counter += 1;

        csv_writer.write_record([
            sample.kernel_time_ns.to_string(),
            sample.sender_ts_val.to_string(),
            sample.src_ip.to_string(),
        ])?;
        csv_writer.flush()?;

        if packet_counter % ANALYSIS_INTERVAL == 0 {
            let hull = compute_lower_hull(points.clone());
            if let Some(slope) = calculate_skew(&hull) {
                let ppm = slope_to_ppm(slope);
                let display_ip = target_filter.unwrap_or(sample.src_ip);
                log::info!(
                    "[Packet #{packet_counter}] Target: {display_ip} | Points: {} | Estimated Skew: {:.2} ppm",
                    points.len(),
                    ppm
                );
            } else {
                log::warn!("Insufficient hull points to compute skew at packet #{packet_counter}");
            }

            csv_writer.flush()?;
        }
    }
}

fn resolve_target_v4(target: Option<IpAddr>) -> Result<Ipv4Addr, Box<dyn Error>> {
    match target {
        Some(IpAddr::V4(ip)) => Ok(ip),
        Some(IpAddr::V6(_)) => Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPv6 targets are not supported for active injection",
        ))),
        None => Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--target-ip is required when active injection is enabled",
        ))),
    }
}

struct RstGuard {
    port: u16,
    installed: bool,
}

impl RstGuard {
    fn install(port: u16) -> io::Result<Self> {
        injector::suppress_rst(port)?;
        Ok(Self {
            port,
            installed: true,
        })
    }
}

impl Drop for RstGuard {
    fn drop(&mut self) {
        if self.installed {
            injector::cleanup_rst(self.port);
        }
    }
}
