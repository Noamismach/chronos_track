use log::{error, info};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpOptionNumbers};
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::{self, TransportChannelType};
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::thread;
use std::time::Duration;

// --- Firewall Logic (RST Suppression) ---

/// חוסם את שליחת פאקטות RST מהפורט שלנו כדי שהקרנל לא ינתק את השיחה
pub fn suppress_rst(port: u16) -> std::io::Result<()> {
    // הפקודה: sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport <PORT> -j DROP
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

/// מנקה את החוק מהפיירוול בסיום הריצה
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

/// פונקציה קריטית שמחשבת את ה-Checksum של ה-TCP כולל ה-Pseudo Header
/// אם החישוב הזה לא מדויק על הביט - הפאקטה תיזרק על ידי השרת
fn calculate_tcp_checksum(
    tcp_packet: &MutableTcpPacket,
    source_ip: &Ipv4Addr,
    dest_ip: &Ipv4Addr,
) -> u16 {
    pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), source_ip, dest_ip)
}

// --- Injection Logic ---

/// הפונקציה הראשית שבונה ושולחת את הפאקטות
pub fn start_injection_loop(target_ip: Ipv4Addr, target_port: u16, src_port: u16) {
    // 1. הגדרת ערוץ Layer 3 (אנחנו בונים את ה-IP וה-TCP, הקרנל עושה את ה-Ethernet)
    let protocol = TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp);
    let (mut tx, _) = transport::transport_channel(4096, protocol)
        .expect("Failed to open transport channel. Are you root?");

    // 2. הכנת הבאפר
    // גודל: IP Header (20) + TCP Header (20) + Options (12)
    const TOTAL_LEN: usize = 20 + 20 + 12;
    let mut buffer = vec![0u8; TOTAL_LEN];

    loop {
        // מציאת ה-IP המקומי שלנו (כדי לשים אותו ב-Header)
        // אנחנו עושים את זה בלולאה למקרה שה-IP ישתנה, אבל אפשר גם פעם אחת בחוץ
        let source_ip = find_local_ip(target_ip).unwrap_or(Ipv4Addr::new(0, 0, 0, 0));

        // --- בניית שכבת ה-IP ---
        let mut ipv4_packet = MutableIpv4Packet::new(&mut buffer).unwrap();
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_total_length(TOTAL_LEN as u16);
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ipv4_packet.set_source(source_ip);
        ipv4_packet.set_destination(target_ip);
        ipv4_packet.set_flags(Ipv4Flags::DontFragment);

        // חישוב Checksum ל-IP (הספרייה עושה את זה אוטומטית אם לא מגדירים, אבל ליתר ביטחון)
        let ip_csum = ipv4::checksum(&ipv4_packet.to_immutable());
        ipv4_packet.set_checksum(ip_csum);

        // --- בניית שכבת ה-TCP ---
        let mut tcp_packet = MutableTcpPacket::new(ipv4_packet.payload_mut()).unwrap();
        tcp_packet.set_source(src_port);
        tcp_packet.set_destination(target_port);
        tcp_packet.set_sequence(rand::random::<u32>());
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(64240);
        tcp_packet.set_data_offset(8); // 5 (Header) + 3 (Options words) = 8 words * 4 = 32 bytes

        // הוספת אופציית Timestamp (Kind 8) ידנית בתוך שדה האפשרויות
        {
            let packet_bytes = tcp_packet.packet_mut();
            let options = &mut packet_bytes[20..32];
            options.fill(0);
            options[0] = TcpOptionNumbers::TIMESTAMPS.0;
            options[1] = 10; // אורך האופציה
            options[2..6].copy_from_slice(&1u32.to_be_bytes()); // TSval
            options[6..10].copy_from_slice(&0u32.to_be_bytes()); // TSecr
            // שני הבתים האחרונים נשארים 0 לצורך ריפוד alignment
        }

        // חישוב Checksum ל-TCP (החלק הקריטי)
        let checksum = calculate_tcp_checksum(&tcp_packet, &source_ip, &target_ip);
        tcp_packet.set_checksum(checksum);

        // --- שליחה ---
        match tx.send_to(ipv4_packet, IpAddr::V4(target_ip)) {
            Ok(_) => info!("Injected SYN to {}", target_ip),
            Err(e) => error!("Failed to send packet: {}", e),
        }

        // המתנה ג'יטר אקראית בין 150ms ל-250ms
        let jitter_ms = rand::thread_rng().gen_range(150..=250);
        thread::sleep(Duration::from_millis(jitter_ms));
    }
}

/// טריק למציאת ה-IP המקומי שדרכו אנחנו יוצאים לאינטרנט
fn find_local_ip(target: Ipv4Addr) -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect((target, 80)).ok()?;
    if let std::net::SocketAddr::V4(addr) = socket.local_addr().ok()? {
        Some(*addr.ip())
    } else {
        None
    }
}
