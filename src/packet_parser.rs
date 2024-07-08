use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn parse_packet(packet: &[u8]) -> Option<(IpAddr, IpAddr, String, u16, u16)> {
    // イーサネットヘッダーをスキップ (通常14バイト)
    let ip_header = packet.get(14..)?;

    // パケットの内容を表示
    //println!("{:02X?}", ip_header);

    // IPバージョンをチェック
    let version = ip_header[0] >> 4;
    match version {
        4 => parse_ipv4(ip_header),
        //6 => parse_ipv6(ip_header),
        _ => None,
    }
}

fn parse_ipv4(ip_header: &[u8]) -> Option<(IpAddr, IpAddr, String, u16, u16)> {
    if ip_header.len() < 20 {
        eprintln!("破損したIPv4パケットが検出されました。");
        return None;
    }

    let src_ip: Ipv4Addr = Ipv4Addr::new(ip_header[12], ip_header[13], ip_header[14], ip_header[15]);
    let dst_ip: Ipv4Addr = Ipv4Addr::new(ip_header[16], ip_header[17], ip_header[18], ip_header[19]);
    let protocol: u8 = ip_header[9];

    let ihl = (ip_header[0] & 0x0F) as usize * 4;
    let tcp_header = ip_header.get(ihl..)?;

    let src_port = u16::from_be_bytes([tcp_header[0], tcp_header[1]]);
    let dst_port = u16::from_be_bytes([tcp_header[2], tcp_header[3]]);

    let protocol_str: String = match protocol {
        1 => parse_icmp(ip_header, false),
        6 => "v4 TCP".to_string(),
        17 => "v4 UDP".to_string(),
        _ => format!("Unknown({})", protocol),
    };

    Some((IpAddr::V4(src_ip), IpAddr::V4(dst_ip), protocol_str, src_port, dst_port))
}

#[allow(dead_code)]
fn parse_ipv6(ip_header: &[u8]) -> Option<(IpAddr, IpAddr, String)> {
    if ip_header.len() < 40 {
        eprintln!("破損したIPv6パケットが検出されました。");
        return None;
    }

    let src_ip: Ipv6Addr = Ipv6Addr::new(
        u16::from_be_bytes([ip_header[8], ip_header[9]]),
        u16::from_be_bytes([ip_header[10], ip_header[11]]),
        u16::from_be_bytes([ip_header[12], ip_header[13]]),
        u16::from_be_bytes([ip_header[14], ip_header[15]]),
        u16::from_be_bytes([ip_header[16], ip_header[17]]),
        u16::from_be_bytes([ip_header[18], ip_header[19]]),
        u16::from_be_bytes([ip_header[20], ip_header[21]]),
        u16::from_be_bytes([ip_header[22], ip_header[23]]),
    );
    let dst_ip: Ipv6Addr = Ipv6Addr::new(
        u16::from_be_bytes([ip_header[24], ip_header[25]]),
        u16::from_be_bytes([ip_header[26], ip_header[27]]),
        u16::from_be_bytes([ip_header[28], ip_header[29]]),
        u16::from_be_bytes([ip_header[30], ip_header[31]]),
        u16::from_be_bytes([ip_header[32], ip_header[33]]),
        u16::from_be_bytes([ip_header[34], ip_header[35]]),
        u16::from_be_bytes([ip_header[36], ip_header[37]]),
        u16::from_be_bytes([ip_header[38], ip_header[39]]),
    );
    let protocol: u8 = ip_header[6];
    let protocol_str: String = match protocol {
        58 => parse_icmp(ip_header, true),
        6 => "v6 TCP".to_string(),
        17 => "v6 UDP".to_string(),
        _ => format!("Unknown({})", protocol),
    };

    Some((IpAddr::V6(src_ip), IpAddr::V6(dst_ip), protocol_str))
}

fn parse_icmp(ip_header: &[u8], is_ipv6: bool) -> String {
    let icmp_type: u8 = if is_ipv6 {
        ip_header.get(40).copied().unwrap_or(0)
    } else {
        let ihl: usize = (ip_header[0] & 0b00001111) as usize;
        ip_header.get(ihl * 4).copied().unwrap_or(0)
    };

    match icmp_type {
        0 => "ICMP echo reply".to_string(),
        8 => "ICMP echo request".to_string(),
        3 => "ICMP destination unreachable".to_string(),
        11 => "ICMP time exceeded".to_string(),
        _ => format!("ICMP(Type:{})", icmp_type),
    }
}