use pcap::{Capture, Device};
use std::sync::{Arc, Mutex};
use std::net::{Ipv4Addr, Ipv6Addr};
use crate::app::App;
use crate::error::{Result, Error};

pub fn start_packet_capture(app: Arc<Mutex<App>>) -> Result<()> {
    let mut current_device: Option<String> = None;

    loop {
        let (device, is_capturing, device_changed) = {
            let mut app = app.lock().map_err(|_| Error::LockError)?;
            let device = app.selected_device.clone();
            let is_capturing = app.is_capturing;
            let device_changed = app.device_changed;
            app.device_changed = false;
            (device, is_capturing, device_changed)
        };

        if !is_capturing {
            current_device = None;
            continue;
        }

        if let Some(device) = device {
            if current_device.as_ref() != Some(&device.name) || device_changed {
                current_device = Some(device.name.clone());
                capture_packets(&device, &app)?;
            }
        }
    }
}

fn capture_packets(device: &Device, app: &Arc<Mutex<App>>) -> Result<()> {
    let mut cap = Capture::from_device(device.clone())?
        .promisc(true)
        .snaplen(65535)
        .timeout(0)
        .immediate_mode(true)
        .buffer_size(3 * 1024 * 1024)
        .open()?;

    while let Ok(packet) = cap.next_packet() {
        let (is_capturing, device_name) = {
            let app = app.lock().map_err(|_| Error::LockError)?;
            (app.is_capturing, app.selected_device.as_ref().map(|d| d.name.clone()))
        };

        if !is_capturing || device_name.as_ref() != Some(&device.name) {
            break;
        }

        if let Some(packet_info) = parse_packet(&packet.data) {
            let mut app = app.lock().map_err(|_| Error::LockError)?;
            app.add_captured_packet(packet_info);
        }
    }

    Ok(())
}

fn parse_packet(packet: &[u8]) -> Option<String> {
    // イーサネットヘッダーをスキップ (通常14バイト)
    let ip_header = packet.get(14..)?;

    // IPバージョンをチェック
    let version = ip_header[0] >> 4;
    match version {
        4 => parse_ipv4(ip_header),
        6 => parse_ipv6(ip_header),
        _ => None,
    }
}

fn parse_ipv4(ip_header: &[u8]) -> Option<String> {
    if ip_header.len() < 20 {
        return None;
    }

    let src_ip = Ipv4Addr::new(ip_header[12], ip_header[13], ip_header[14], ip_header[15]);
    let dst_ip = Ipv4Addr::new(ip_header[16], ip_header[17], ip_header[18], ip_header[19]);
    let protocol: u8 = ip_header[9];

    let ihl = (ip_header[0] & 0x0F) as usize * 4;
    let tcp_header = ip_header.get(ihl..)?;

    let src_port = u16::from_be_bytes([tcp_header[0], tcp_header[1]]);
    let dst_port = u16::from_be_bytes([tcp_header[2], tcp_header[3]]);

    let protocol_str = match protocol {
        1 => "ICMP",    // Internet Control Message Protocol
        2 => "IGMP",    // Internet Group Management Protocol
        6 => "TCP",     // Transmission Control Protocol
        17 => "UDP",    // User Datagram Protocol
        41 => "IPv6",   // Internet Protocol Version 6
        47 => "GRE",    // Generic Routing Encapsulation
        50 => "ESP",    // Encapsulating Security Payload (IPsec)
        51 => "AH",     // Authentication Header (IPsec)
        58 => "ICMPv6", // Internet Control Message Protocol for IPv6
        89 => "OSPF",   // Open Shortest Path First
        103 => "PIM",   // Protocol Independent Multicast
        112 => "VRRP",  // Virtual Router Redundancy Protocol
        132 => "SCTP",  // Stream Control Transmission Protocol
        136 => "UDPLite", // Lightweight User Datagram Protocol
        _ => "Unknown",
    };

    Some(format!("{}:{} > {}:{} {}", src_ip, src_port, dst_ip, dst_port, protocol_str))
}

fn parse_ipv6(ip_header: &[u8]) -> Option<String> {
    if ip_header.len() < 40 {
        return None;
    }

    let src_ip = Ipv6Addr::new(
        u16::from_be_bytes([ip_header[8], ip_header[9]]),
        u16::from_be_bytes([ip_header[10], ip_header[11]]),
        u16::from_be_bytes([ip_header[12], ip_header[13]]),
        u16::from_be_bytes([ip_header[14], ip_header[15]]),
        u16::from_be_bytes([ip_header[16], ip_header[17]]),
        u16::from_be_bytes([ip_header[18], ip_header[19]]),
        u16::from_be_bytes([ip_header[20], ip_header[21]]),
        u16::from_be_bytes([ip_header[22], ip_header[23]]),
    );
    let dst_ip = Ipv6Addr::new(
        u16::from_be_bytes([ip_header[24], ip_header[25]]),
        u16::from_be_bytes([ip_header[26], ip_header[27]]),
        u16::from_be_bytes([ip_header[28], ip_header[29]]),
        u16::from_be_bytes([ip_header[30], ip_header[31]]),
        u16::from_be_bytes([ip_header[32], ip_header[33]]),
        u16::from_be_bytes([ip_header[34], ip_header[35]]),
        u16::from_be_bytes([ip_header[36], ip_header[37]]),
        u16::from_be_bytes([ip_header[38], ip_header[39]]),
    );
    let next_header: u8 = ip_header[6];

    let tcp_header = ip_header.get(40..)?;

    let src_port = u16::from_be_bytes([tcp_header[0], tcp_header[1]]);
    let dst_port = u16::from_be_bytes([tcp_header[2], tcp_header[3]]);

    let protocol_str = match next_header {
        0 => "HOPOPT",   // Hop-by-Hop Options
        6 => "TCP",      // Transmission Control Protocol
        17 => "UDP",     // User Datagram Protocol
        43 => "IPv6-Route", // Routing Header for IPv6
        44 => "IPv6-Frag",  // Fragment Header for IPv6
        50 => "ESP",     // Encapsulating Security Payload
        51 => "AH",      // Authentication Header
        58 => "ICMPv6",  // Internet Control Message Protocol for IPv6
        59 => "IPv6-NoNxt", // No Next Header for IPv6
        60 => "IPv6-Opts",  // Destination Options for IPv6
        132 => "SCTP",   // Stream Control Transmission Protocol
        135 => "Mobility Header", // Mobility Support for IPv6
        139 => "HIP",    // Host Identity Protocol
        140 => "Shim6",  // Shim6 Protocol
        _ => "Unknown",
    };

    Some(format!("{}:{} > {}:{} {}", src_ip, src_port, dst_ip, dst_port, protocol_str))
}