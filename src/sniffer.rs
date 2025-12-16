// Purpose: Capture kernel-timestamped TCP packets for Chronos-Track analysis.
// Author: Research Project
// Disclaimer: For educational and defensive research purposes only.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

use libc::{self, c_int};
use log::{debug, error};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{TcpOptionNumbers, TcpPacket};
use socket2::{Domain, Protocol, Socket, Type};

#[cfg(not(target_os = "linux"))]
compile_error!("Chronos-Track sniffer currently supports only Linux via SO_TIMESTAMPING.");

const MAX_FRAME_SIZE: usize = 65536;
const CMSG_BUFFER_SIZE: usize = 512;
const TIMESTAMP_FLAGS: c_int = (libc::SOF_TIMESTAMPING_SOFTWARE
    | libc::SOF_TIMESTAMPING_RX_SOFTWARE
    | libc::SOF_TIMESTAMPING_RAW_HARDWARE) as c_int;

/// Minimal representation of a captured packet: kernel timestamp, remote TSval, and source IP.
#[derive(Debug, Clone)]
pub struct PacketSample {
    pub kernel_time_ns: u64,
    pub sender_ts_val: u32,
    pub src_ip: IpAddr,
}

/// Creates an AF_PACKET/RAW socket pinned to an interface with SO_TIMESTAMPING enabled.
pub fn create_precision_socket(interface_name: &str) -> io::Result<Socket> {
    let domain = Domain::from(libc::AF_PACKET);
    let ty = Type::from(libc::SOCK_RAW);
    let protocol = Protocol::from((libc::ETH_P_ALL as i16).to_be() as i32);
    let socket = Socket::new(domain, ty, Some(protocol))?;
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;

    bind_to_interface(&socket, interface_name)?;
    enable_timestamping(socket.as_raw_fd())?;

    Ok(socket)
}

/// Receives frames until a TCP timestamp option is parsed, returning the first viable sample.
pub fn recv_packet(socket: &Socket) -> io::Result<Option<PacketSample>> {
    let mut frame = [0u8; MAX_FRAME_SIZE];

    loop {
        let (frame_len, kernel_ns) = recv_with_timestamp(socket, &mut frame)?;
        if frame_len == 0 {
            continue;
        }
        debug!("Received frame len={frame_len}");

        if let Some(sample) = parse_sample(&frame[..frame_len], kernel_ns) {
            return Ok(Some(sample));
        }
    }
}

fn bind_to_interface(socket: &Socket, interface_name: &str) -> io::Result<()> {
    let c_name = CString::new(interface_name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name contains interior null byte",
        )
    })?;

    let if_index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if if_index == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as libc::sa_family_t;
    addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    addr.sll_ifindex = if_index as i32;

    let ret = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };

    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn enable_timestamping(fd: RawFd) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPING,
            &TIMESTAMP_FLAGS as *const c_int as *const libc::c_void,
            std::mem::size_of_val(&TIMESTAMP_FLAGS) as libc::socklen_t,
        )
    };

    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn recv_with_timestamp(socket: &Socket, buffer: &mut [u8]) -> io::Result<(usize, u64)> {
    let fd = socket.as_raw_fd();
    let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut control = [0u8; CMSG_BUFFER_SIZE];

    loop {
        let mut iov = libc::iovec {
            iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
            iov_len: buffer.len(),
        };

        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = &mut name as *mut _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = control.len();

        let received = unsafe { libc::recvmsg(fd, &mut msg, 0) };
        if received < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }

        let timestamp_ns = extract_kernel_time_ns(&msg).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "missing SCM_TIMESTAMPING control message",
            )
        })?;

        return Ok((received as usize, timestamp_ns));
    }
}

fn extract_kernel_time_ns(msg: &libc::msghdr) -> Option<u64> {
    unsafe {
        let msg_ptr = msg as *const libc::msghdr;
        let mut cmsg = libc::CMSG_FIRSTHDR(msg_ptr);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_TIMESTAMPING
            {
                let ts_ptr = libc::CMSG_DATA(cmsg) as *const libc::timespec;
                for idx in 0..3 {
                    let ts = *ts_ptr.add(idx);
                    if ts.tv_sec != 0 || ts.tv_nsec != 0 {
                        return Some(timespec_to_ns(ts));
                    }
                }
            }
            cmsg = libc::CMSG_NXTHDR(msg_ptr, cmsg);
        }
    }
    None
}

fn timespec_to_ns(ts: libc::timespec) -> u64 {
    let secs = ts.tv_sec as i128;
    let nanos = ts.tv_nsec as i128;
    (secs * 1_000_000_000 + nanos).max(0) as u64
}

fn parse_sample(frame: &[u8], kernel_time_ns: u64) -> Option<PacketSample> {
    let eth = EthernetPacket::new(frame)?;
    debug!("EtherType={:?}", eth.get_ethertype());
    match eth.get_ethertype() {
        EtherTypes::Ipv4 => parse_ipv4(&eth, kernel_time_ns),
        EtherTypes::Ipv6 => parse_ipv6(&eth, kernel_time_ns),
        _ => None,
    }
}

fn parse_ipv4(eth: &EthernetPacket, kernel_time_ns: u64) -> Option<PacketSample> {
    let ipv4 = Ipv4Packet::new(eth.payload())?;
    let src = Ipv4Addr::from(ipv4.get_source());
    let proto = ipv4.get_next_level_protocol();
    debug!("IPv4 detected. Source: {src} Proto: {proto:?}");
    if proto != IpNextHeaderProtocols::Tcp {
        debug!("Dropped - Not TCP (proto={proto:?})");
        return None;
    }

    let tcp = TcpPacket::new(ipv4.payload())?;
    let ts = extract_tcp_timestamp(&tcp)?;
    let src_ip = IpAddr::V4(Ipv4Addr::from(ipv4.get_source()));

    Some(PacketSample {
        kernel_time_ns,
        sender_ts_val: ts,
        src_ip,
    })
}

fn parse_ipv6(eth: &EthernetPacket, kernel_time_ns: u64) -> Option<PacketSample> {
    let ipv6 = Ipv6Packet::new(eth.payload())?;
    if ipv6.get_next_header() != IpNextHeaderProtocols::Tcp {
        return None;
    }

    let tcp = TcpPacket::new(ipv6.payload())?;
    let ts = extract_tcp_timestamp(&tcp)?;
    let src_ip = IpAddr::V6(Ipv6Addr::from(ipv6.get_source()));

    Some(PacketSample {
        kernel_time_ns,
        sender_ts_val: ts,
        src_ip,
    })
}

fn extract_tcp_timestamp(tcp: &TcpPacket) -> Option<u32> {
    debug!("Checking TCP Options...");
    for option in tcp.get_options_iter() {
        let number = option.get_number();
        debug!("Found Option Kind={number:?}");
        if number == TcpOptionNumbers::TIMESTAMPS {
            let payload = option.payload();
            if payload.len() >= 8 {
                let ts_val = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                return Some(ts_val);
            }
            error!(
                "Timestamp option payload too short: len={} (expected >= 8)",
                payload.len()
            );
        }
    }
    None
}
