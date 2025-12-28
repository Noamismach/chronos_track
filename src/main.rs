// Purpose: Coordinate injection, packet capture, and convex-hull analysis for Chronos-Track.
// Author: Research Project
// Disclaimer: For educational and defensive research purposes only.

mod analysis;
mod config;
mod injector;
mod sniffer;
mod ui;

use std::error::Error;
use std::fs::File;
use std::io::{self, BufWriter};
use std::process;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use analysis::{calculate_skew, interpret_report, Interpretation, Observation, SkewReport};
use config::Config;
use socket2::Socket;
use std::net::{IpAddr, Ipv4Addr};
use ui::UiState;

const ANALYSIS_INTERVAL: u64 = 50;
const NS_PER_SEC: f64 = 1_000_000_000.0;
const SOURCE_PORT: u16 = 54_321;

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
    let target_port = cfg.target_port;
    let observations: Arc<Mutex<Vec<Observation>>> = Arc::new(Mutex::new(Vec::new()));
    let latest_report: Arc<Mutex<Option<SkewReport>>> = Arc::new(Mutex::new(None));
    let latest_interpretation: Arc<Mutex<Option<Interpretation>>> = Arc::new(Mutex::new(None));
    let status_text = Arc::new(Mutex::new(String::from("Waiting for packets...")));
    let adaptive_interval = Arc::new(AtomicU64::new(200));
    let running = Arc::new(AtomicBool::new(true));
    let start_time = Instant::now();

    log::info!(
        "Chronos-Track starting on interface {} (target={:?})",
        cfg.interface,
        target_filter
    );

    let _rst_guard = RstGuard::install(SOURCE_PORT)?;

    ctrlc::set_handler({
        let running = Arc::clone(&running);
        move || {
            running.store(false, Ordering::Relaxed);
        }
    })?;

    let injector_interval = Arc::clone(&adaptive_interval);
    thread::spawn(move || {
        injector::start_injection_loop(
            injection_target,
            target_port,
            SOURCE_PORT,
            injector_interval,
        );
    });

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

    let file = File::create("measurements.csv")?;
    let csv_writer = csv::Writer::from_writer(BufWriter::new(file));

    let capture_handle = spawn_capture_thread(
        socket,
        csv_writer,
        target_filter,
        Arc::clone(&observations),
        Arc::clone(&latest_report),
        Arc::clone(&latest_interpretation),
        Arc::clone(&status_text),
        Arc::clone(&adaptive_interval),
        Arc::clone(&running),
    );

    let ui_state = UiState {
        target_ip: target_filter.map(|ip| ip.to_string()),
        target_port,
        start_time,
        status: Arc::clone(&status_text),
        observations: Arc::clone(&observations),
        latest_report: Arc::clone(&latest_report),
        latest_interpretation: Arc::clone(&latest_interpretation),
        running: Arc::clone(&running),
    };

    let ui_result = ui::run(ui_state);

    running.store(false, Ordering::Relaxed);
    if let Err(err) = capture_handle.join() {
        log::error!("Capture thread panicked: {:?}", err);
    }

    let samples = {
        let data = observations
            .lock()
            .expect("observation buffer poisoned");
        if let Some(report) = calculate_skew(&data) {
            print_exit_report(report, data.len());
        } else {
            println!(
                "Chronos-Track summary: insufficient observations ({} samples).",
                data.len()
            );
        }
        data.len()
    };

    if samples == 0 {
        log::warn!("No samples collected during session.");
    }

    ui_result.map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

    Ok(())
}

/// Resolves the CLI-provided IP filter into an IPv4 address required for active injection.
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

/// RAII helper that installs an iptables RST drop rule and ensures it is removed on exit.
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

/// Emits a final skew summary when Chronos-Track terminates gracefully.
fn print_exit_report(report: SkewReport, samples: usize) {
    let interpretation = interpret_report(&report);
    println!("\n=== Chronos-Track Exit Report ===");
    println!("Samples captured: {}", samples);
    println!("Slope: {:.9}", report.slope);
    println!("Clock Skew: {:.3} ppm", report.ppm);
    println!("R²: {:.4}", report.r_squared);
    println!("Classification: {}", report.verdict);
    println!("=================================");
    println!("--- 🧠 CHRONOS INTELLIGENCE ---");
    println!("Signal Quality: {}", interpretation.stability_desc);
    println!("Hardware Est.:  {}", interpretation.hardware_quality);
    println!("FINAL VERDICT:  {}", interpretation.human_verdict);
    println!("--------------------------------\n");
}

fn spawn_capture_thread(
    socket: Socket,
    csv_writer: csv::Writer<BufWriter<File>>,
    target_filter: Option<IpAddr>,
    observations: Arc<Mutex<Vec<Observation>>>,
    latest_report: Arc<Mutex<Option<SkewReport>>>,
    latest_interpretation: Arc<Mutex<Option<Interpretation>>>,
    status_text: Arc<Mutex<String>>,
    adaptive_interval: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        if let Err(err) = capture_loop(
            socket,
            csv_writer,
            target_filter,
            observations,
            latest_report,
            latest_interpretation,
            status_text,
            adaptive_interval,
            running,
        ) {
            log::error!("Capture loop terminated: {err}");
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn capture_loop(
    socket: Socket,
    mut csv_writer: csv::Writer<BufWriter<File>>,
    target_filter: Option<IpAddr>,
    observations: Arc<Mutex<Vec<Observation>>>,
    latest_report: Arc<Mutex<Option<SkewReport>>>,
    latest_interpretation: Arc<Mutex<Option<Interpretation>>>,
    status_text: Arc<Mutex<String>>,
    adaptive_interval: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    csv_writer.write_record(["kernel_time_ns", "sender_ts_val", "src_ip"])?;
    csv_writer.flush()?;

    let mut packet_counter: u64 = 0;

    while running.load(Ordering::Relaxed) {
        let sample = match sniffer::recv_packet(&socket) {
            Ok(Some(sample)) => sample,
            Ok(None) => continue,
            Err(err) => {
                if err.kind() == io::ErrorKind::WouldBlock {
                    continue;
                }
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
            let mut guard = observations
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

        if let Ok(mut status) = status_text.lock() {
            *status = format!(
                "Capturing | samples={} | last src={}",
                packet_counter,
                sample.src_ip
            );
        }

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

                let interpretation = interpret_report(&report);
                if let Ok(mut guard) = latest_report.lock() {
                    *guard = Some(report.clone());
                }
                if let Ok(mut guard) = latest_interpretation.lock() {
                    *guard = Some(interpretation);
                }

                let new_interval = if report.r_squared > 0.9999 {
                    10
                } else if report.r_squared > 0.99 {
                    100
                } else {
                    500
                };
                adaptive_interval.store(new_interval, Ordering::Relaxed);
            } else {
                log::warn!("Insufficient hull points to compute skew at packet #{packet_counter}");
            }
        }
    }

    if let Ok(mut status) = status_text.lock() {
        *status = String::from("Stopped (awaiting shutdown)");
    }

    Ok(())
}
