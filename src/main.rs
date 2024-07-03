use pcap::{Device, Capture};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 利用可能なネットワークインターフェースを取得
    let devices: Vec<Device> = Device::list()?;
    println!("利用可能なデバイス:");
    for (i, device) in devices.iter().enumerate() {
        println!("{}. {}", i + 1, device.name);
    }

    print!("使用するデバイスの番号を入力してください: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let device_index: usize = input.trim().parse::<usize>()? - 1;
    let device = devices.get(device_index).ok_or("無効なデバイス番号")?;

    println!("選択されたデバイス: {}", device.name);

    // キャプチャを開始
    let mut cap = Capture::from_device(device.clone())?
        .promisc(true)
        .snaplen(65535)
        .open()?;

    println!("パケットキャプチャを開始します...");

    // パケットをキャプチャして表示
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some((src_ip, dst_ip, protocol)) = parse_packet(&packet.data) {
                    println!("{} > {} {}", src_ip, dst_ip, protocol);
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                eprintln!("パケットの取得中にエラーが発生しました: {}", e);
                break;
            }
        }
    }

    Ok(())
}

fn parse_packet(packet: &[u8]) -> Option<(IpAddr, IpAddr, String)> {
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

fn parse_ipv4(ip_header: &[u8]) -> Option<(IpAddr, IpAddr, String)> {
    if ip_header.len() < 20 {
        return None;
    }

    let src_ip = Ipv4Addr::new(ip_header[12], ip_header[13], ip_header[14], ip_header[15]);
    let dst_ip = Ipv4Addr::new(ip_header[16], ip_header[17], ip_header[18], ip_header[19]);
    let protocol = ip_header[9];
    let protocol_str = match protocol {
        1 => parse_icmp(ip_header, false),
        6 => "TCP".to_string(),
        17 => "UDP".to_string(),
        _ => format!("Unknown({})", protocol),
    };
    Some((IpAddr::V4(src_ip), IpAddr::V4(dst_ip), protocol_str))
}

fn parse_ipv6(ip_header: &[u8]) -> Option<(IpAddr, IpAddr, String)> {
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
    let protocol = ip_header[6];
    let protocol_str = match protocol {
        58 => parse_icmp(ip_header, true),
        6 => "TCP".to_string(),
        17 => "UDP".to_string(),
        _ => format!("Unknown({})", protocol),
    };
    Some((IpAddr::V6(src_ip), IpAddr::V6(dst_ip), protocol_str))
}

fn parse_icmp(ip_header: &[u8], is_ipv6: bool) -> String {
    let icmp_type = if is_ipv6 {
        ip_header.get(40).copied().unwrap_or(0)
    } else {
        let ihl = (ip_header[0] & 0x0F) as usize;
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