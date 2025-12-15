// Purpose: Craft and inject stealth TCP probes while handling firewall hygiene.
// Author: Research Project
// Disclaimer: For educational and defensive research purposes only.

use log::{error, info};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpOptionNumbers};
use pnet::packet::MutablePacket;
use pnet::transport::{self, TransportChannelType};
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// --- Firewall Logic (RST Suppression) ---

/// Adds an iptables rule that drops outbound RST packets so Linux does not tear down the probes.
pub fn suppress_rst(port: u16) -> std::io::Result<()> {
    // Equivalent to: sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport <PORT> -j DROP
    let status = Command::new("iptables")
        .args(&[
            "-A",
            "OUTPUT",
            "-p",
            "tcp",
            "--tcp-flags",
            "RST",
            "RST",
            "--sport",
            &port.to_string(),
            "-j",
            "DROP",
        ])
        .status()?;

    if !status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to add iptables rule for RST suppression",
        ));
    }
    info!(
        "Firewall rule added: Dropping RST packets from port {}",
        port
    );
    Ok(())
}

/// Removes the iptables rule that was added for RST suppression.
pub fn cleanup_rst(port: u16) {
    let _ = Command::new("iptables")
        .args(&[
            "-D",
            "OUTPUT",
            "-p",
            "tcp",
            "--tcp-flags",
            "RST",
            "RST",
            "--sport",
            &port.to_string(),
            "-j",
            "DROP",
        ])
        .status();
    info!("Firewall rule removed for port {}", port);
}

// --- Checksum Logic (The Math) ---

// Computes the TCP checksum (including the pseudo header). Accuracy is critical or packets get dropped.
fn calculate_tcp_checksum(
    tcp_packet: &MutableTcpPacket,
    source_ip: &Ipv4Addr,
    dest_ip: &Ipv4Addr,
) -> u16 {
    pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), source_ip, dest_ip)
}

// --- Injection Logic ---

/// Builds raw IPv4/TCP SYN probes with timestamps and sends them in a loop.
pub fn start_injection_loop(
    target_ip: Ipv4Addr,
    target_port: u16,
    src_port: u16,
    interval_ms: Arc<AtomicU64>,
) {
    // Step 1: open a Layer-3 transport channel so the kernel only wraps Ethernet.
    let protocol = TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp);
    let (mut tx, _) = transport::transport_channel(4096, protocol)
        .expect("Failed to open transport channel. Are you root?");

    // Step 2: prepare a fixed buffer (20 bytes IP + 20 bytes TCP + 12 bytes options).
    const TOTAL_LEN: usize = 20 + 20 + 12;
    let mut buffer = vec![0u8; TOTAL_LEN];

    loop {
        // Refresh the local IP used as the spoofed source in case routes change during scanning.
        let source_ip = find_local_ip(target_ip).unwrap_or(Ipv4Addr::new(0, 0, 0, 0));

        // Build the IPv4 header.
        let mut ipv4_packet = MutableIpv4Packet::new(&mut buffer).unwrap();
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_total_length(TOTAL_LEN as u16);
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ipv4_packet.set_source(source_ip);
        ipv4_packet.set_destination(target_ip);
        ipv4_packet.set_flags(Ipv4Flags::DontFragment);

        // Recompute the IPv4 checksum explicitly for clarity.
        let ip_csum = ipv4::checksum(&ipv4_packet.to_immutable());
        ipv4_packet.set_checksum(ip_csum);

        // Build the TCP header and timestamp option payload.
        let mut tcp_packet = MutableTcpPacket::new(ipv4_packet.payload_mut()).unwrap();
        tcp_packet.set_source(src_port);
        tcp_packet.set_destination(target_port);
        tcp_packet.set_sequence(rand::random::<u32>());
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(64240);
        tcp_packet.set_data_offset(8); // 5 (Header) + 3 (Options words) = 8 words * 4 = 32 bytes

        // Encode the TCP timestamp option manually so it is always present in the probe.
        {
            let packet_bytes = tcp_packet.packet_mut();
            let options = &mut packet_bytes[20..32];
            options.fill(0);
            options[0] = TcpOptionNumbers::TIMESTAMPS.0;
            options[1] = 10; // Option length
            options[2..6].copy_from_slice(&1u32.to_be_bytes()); // TSval
            options[6..10].copy_from_slice(&0u32.to_be_bytes()); // TSecr
            // Final two bytes remain zero for padding alignment.
        }

        // חישוב Checksum ל-TCP (החלק הקריטי)
        let checksum = calculate_tcp_checksum(&tcp_packet, &source_ip, &target_ip);
        tcp_packet.set_checksum(checksum);

        // Transmit the crafted probe.
        match tx.send_to(ipv4_packet, IpAddr::V4(target_ip)) {
            Ok(_) => info!("Injected SYN to {}", target_ip),
            Err(e) => error!("Failed to send packet: {}", e),
        }

        // Adaptive sleep with jitter derived from the shared interval.
        let base_interval = interval_ms.load(Ordering::Relaxed).max(1);
        let jitter_cap = base_interval / 5;
        let jitter = if jitter_cap > 0 {
            rand::thread_rng().gen_range(0..=jitter_cap)
        } else {
            0
        };
        let sleep_time = base_interval + jitter;
        thread::sleep(Duration::from_millis(sleep_time));
    }
}

/// Finds the current outbound IPv4 address by opening a temporary UDP socket to the target.
fn find_local_ip(target: Ipv4Addr) -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect((target, 80)).ok()?;
    if let std::net::SocketAddr::V4(addr) = socket.local_addr().ok()? {
        Some(*addr.ip())
    } else {
        None
    }
}
