mod analysis;
mod config;
mod injector;
mod sniffer;

use std::error::Error;
use std::fs::File;
use std::io::{self, BufWriter};
use std::process;
use std::sync::{Arc, Mutex};
use std::thread;

use analysis::{Observation, SkewReport, calculate_skew};
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
    let observations: Arc<Mutex<Vec<Observation>>> = Arc::new(Mutex::new(Vec::new()));

    log::info!(
        "Chronos-Track starting on interface {} (target={:?})",
        cfg.interface,
        target_filter
    );

    let _rst_guard = RstGuard::install(SOURCE_PORT)?;

    ctrlc::set_handler({
        let port = SOURCE_PORT;
        let shared = Arc::clone(&observations);
        move || {
            match shared.lock() {
                Ok(data) => {
                    if let Some(report) = calculate_skew(&data) {
                        print_exit_report(report, data.len());
                    } else {
                        println!(
                            "Chronos-Track summary: insufficient observations ({} samples).",
                            data.len()
                        );
                    }
                }
                Err(_) => println!(
                    "Chronos-Track summary: observation buffer poisoned, unable to compute skew."
                ),
            }

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

    let shared_observations = Arc::clone(&observations);
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

        let observation = Observation::new(
            sample.kernel_time_ns as f64 / NS_PER_SEC,
            sample.sender_ts_val as f64,
        );

        packet_counter += 1;
        let mut snapshot: Option<Vec<Observation>> = None;
        {
            let mut guard = shared_observations
                .lock()
                .expect("observation buffer poisoned");
            guard.push(observation);
            if packet_counter % ANALYSIS_INTERVAL == 0 {
                snapshot = Some(guard.clone());
            }
        }

        csv_writer.write_record([
            sample.kernel_time_ns.to_string(),
            sample.sender_ts_val.to_string(),
            sample.src_ip.to_string(),
        ])?;
        csv_writer.flush()?;

        if let Some(data) = snapshot {
            if let Some(report) = calculate_skew(&data) {
                let display_ip = target_filter.unwrap_or(sample.src_ip);
                log::info!(
                    "[Packet #{packet_counter}] Target: {display_ip} | Points: {} | Slope: {:.9} | Skew: {:.2} ppm | R²: {:.3} | Verdict: {}",
                    data.len(),
                    report.slope,
                    report.ppm,
                    report.r_squared,
                    report.verdict
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

fn print_exit_report(report: SkewReport, samples: usize) {
    println!("\n=== Chronos-Track Exit Report ===");
    println!("Samples captured: {}", samples);
    println!("Slope: {:.9}", report.slope);
    println!("Clock Skew: {:.3} ppm", report.ppm);
    println!("R²: {:.4}", report.r_squared);
    println!("Classification: {}", report.verdict);
    println!("=================================\n");
}
