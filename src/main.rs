use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::time::{Instant, Duration};
use std::collections::HashMap;

use pcap::{Capture, Device};

// TCPフラグの定義
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;
const TCP_URG: u8 = 0x20;

// TCPセッションの状態を表す列挙型
#[derive(Debug, PartialEq, Clone)]
enum TcpState {
    Listen, //TCPモジュールはリモートホストからのコネクション要求を待っている。パッシブオープンの後で入る状態と同じ。
    SynSent, //TCPモジュールは自分のコネクション要求の送信を終え、応答確認と対応するコネクション要求を待っている。
    SynReceived, //TCPモジュールは同期（SYN）セグメントを受信し、対応する同期（SYN/ACK）セグメントを送って、コネクション応答確認を待っている。
    Established, //コネクションが開かれ、データ転送が行える通常の状態になっている。受信されたデータは全てアプリケーションプロセスに渡せる。
    FinWait1, //TCPモジュールはリモートホストからのコネクション終了要求か、すでに送った終了要求の応答確認を待っている。
    FinWait2, //この状態に入るのは、TCPモジュールがリモートホストからの終了要求を待っているときである。
    CloseWait, //TCPモジュールはアプリケーションプロセスからのコネクション終了要求を待っている。
    Closing, //TCPモジュールはリモートホストからのコネクション終了要求を待っている。
    LastAck, //リモートホストに送ったコネクション終了要求について、TCPモジュールがその応答確認を待っている
    TimeWait, //コネクション終了要求応答確認をリモートホストが確実に受取るのに必要な時間が経過するまで、TCPモジュールは待機している
    Closed, //コネクションは全く存在せず、確立段階にも入っていない
    //状態移管図↓
    //https://camo.qiitausercontent.com/24d35109620da317520dc832e55b60d1e730db04/68747470733a2f2f71696974612d696d6167652d73746f72652e73332e616d617a6f6e6177732e636f6d2f302f323831332f32313639633437332d613764332d353666642d643734382d3238326331346138343637342e6a706567
}

// TCPストリームを表す構造体
#[derive(Debug)]
struct TcpStream {
    state: TcpState,
    client_isn: u32,
    server_isn: u32,
    client_next_seq: u32,
    server_next_seq: u32,
    client_data: Vec<u8>,
    server_data: Vec<u8>,
    last_activity: Instant,
    client_window: u16,
    server_window: u16,
    client_mss: u16,
    server_mss: u16,
}

impl TcpStream {
    fn new(client_isn: u32, server_isn: u32) -> Self {
        TcpStream {
            state: TcpState::SynSent,
            client_isn,
            server_isn,
            client_next_seq: client_isn.wrapping_add(1),
            server_next_seq: server_isn,
            client_data: Vec::new(),
            server_data: Vec::new(),
            last_activity: Instant::now(),
            client_window: 0,
            server_window: 0,
            client_mss: 1460,  // デフォルト値
            server_mss: 1460,  // デフォルト値
        }
    }

    fn update(&mut self, is_from_client: bool, seq: u32, ack: u32, flags: u8, data: &[u8], window: u16) {
        self.last_activity = Instant::now();

        if is_from_client {
            if seq == self.client_next_seq {
                self.client_data.extend_from_slice(data);
                self.client_next_seq = self.client_next_seq.wrapping_add(data.len() as u32);
            }
            if flags & TCP_ACK != 0 {
                self.server_next_seq = ack;
            }
            self.client_window = window;
        } else {
            if seq == self.server_next_seq {
                self.server_data.extend_from_slice(data);
                self.server_next_seq = self.server_next_seq.wrapping_add(data.len() as u32);
            }
            if flags & TCP_ACK != 0 {
                self.client_next_seq = ack;
            }
            self.server_window = window;
        }

        // 状態遷移の処理
        self.state = match (self.state.clone(), flags) {
            (TcpState::Listen, TCP_SYN) => TcpState::SynReceived,
            (TcpState::SynSent, TCP_SYN | TCP_ACK) => TcpState::Established,
            (TcpState::SynReceived, TCP_ACK) => TcpState::Established,
            (TcpState::Established, TCP_FIN) => TcpState::FinWait1,
            (TcpState::FinWait1, TCP_FIN | TCP_ACK) => TcpState::FinWait2,
            (TcpState::FinWait2, TCP_ACK) => TcpState::TimeWait,
            (TcpState::CloseWait, TCP_FIN) => TcpState::LastAck,
            (TcpState::LastAck, TCP_ACK) => TcpState::Closed,
            (TcpState::TimeWait, _) if Instant::now().duration_since(self.last_activity) > Duration::from_secs(120) => TcpState::Closed,
            (state, _) => state,
        };
    }

    fn set_mss(&mut self, is_client: bool, mss: u16) {
        if is_client {
            self.client_mss = mss;
        } else {
            self.server_mss = mss;
        }
    }
}

type TcpStreamKey = (Ipv4Addr, u16, Ipv4Addr, u16);

// IPヘッダーの構造体
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version|  IHL  |Type of Service|          Total Length         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Identification        |Flags|      Fragment Offset    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Time to Live |    Protocol   |         Header Checksum       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Source Address                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Destination Address                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug)]
struct IpHeader {
    version: u8,
    ihl: u8,
    dscp_ecn: u8,
    total_length: u16,
    identification: u16,
    flags_fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    header_checksum: u16,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
}

// IPヘッダーのパース関数
fn parse_ip_header(data: &[u8]) -> Option<(IpHeader, usize)> {
    if data.len() < 20 {
        return None;
    }

    let version = (data[0] >> 4) & 0xF;
    if version != 4 {
        return None;  // IPv4のみをサポート
    }

    let ihl = (data[0] & 0xF) as usize * 4;
    let dscp_ecn = data[1];
    let total_length = u16::from_be_bytes([data[2], data[3]]);
    let identification = u16::from_be_bytes([data[4], data[5]]);
    let flags_fragment_offset = u16::from_be_bytes([data[6], data[7]]);
    let ttl = data[8];
    let protocol = data[9];
    let header_checksum = u16::from_be_bytes([data[10], data[11]]);
    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    Some((
        IpHeader {
            version,
            ihl: ihl as u8,
            dscp_ecn,
            total_length,
            identification,
            flags_fragment_offset,
            ttl,
            protocol,
            header_checksum,
            src_ip,
            dst_ip,
        },
        ihl
    ))
}

// TCPヘッダーの構造体
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Source Port          |       Destination Port        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Sequence Number                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Acknowledgment Number                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Data |           |U|A|P|R|S|F|                               |
// | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
// |       |           |G|K|H|T|N|N|                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Checksum            |         Urgent Pointer        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug)]
struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    data_offset: u8,
    flags: u8,
    window: u16,
    checksum: u16,
    urgent_ptr: u16,
}

// TCPヘッダーのパース関数
fn parse_tcp_header(data: &[u8]) -> Option<(TcpHeader, usize)> {
    if data.len() < 20 {
        return None;
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]); //2byte (16bit)
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]); //4byte (32bit)
    let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset = (data[12] >> 4) & 0xF;
    let flags = data[13];
    let window = u16::from_be_bytes([data[14], data[15]]);
    let checksum = u16::from_be_bytes([data[16], data[17]]);
    let urgent_ptr = u16::from_be_bytes([data[18], data[19]]);

    Some((
        TcpHeader {
            src_port,
            dst_port,
            seq_num,
            ack_num,
            data_offset,
            flags,
            window,
            checksum,
            urgent_ptr,
        },
        data_offset as usize * 4
    ))
}

// TCPオプションの解析関数
fn parse_tcp_options(data: &[u8]) -> Option<u16> {
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            0 => break,  // End of options
            1 => i += 1, // NOP
            2 if data.len() >= i + 4 => {
                // MSS option
                return Some(u16::from_be_bytes([data[i+2], data[i+3]]));
            }
            _ if data.len() > i + 1 => i += data[i+1] as usize,
            _ => break,
        }
    }
    None
}

fn process_packet(packet: &pcap::Packet, streams: &mut HashMap<TcpStreamKey, TcpStream>) {
    let eth_header_size = 14;  // Ethernetヘッダーのサイズ
    if packet.data.len() <= eth_header_size {
        return;
    }

    let ip_data = &packet.data[eth_header_size..];

    if let Some((ip_header, ip_header_size)) = parse_ip_header(ip_data) {
        if ip_header.protocol != 6 {  // TCPのプロトコル番号は6
            return;
        }

        let tcp_data = &ip_data[ip_header_size..];
        if let Some((tcp_header, tcp_header_size)) = parse_tcp_header(tcp_data) {
            let payload = &tcp_data[tcp_header_size..];
            let stream_key = (ip_header.src_ip, tcp_header.src_port, ip_header.dst_ip, tcp_header.dst_port);
            let reverse_key = (ip_header.dst_ip, tcp_header.dst_port, ip_header.src_ip, tcp_header.src_port);

            let is_from_client = if streams.contains_key(&stream_key) {
                true
            } else if streams.contains_key(&reverse_key) {
                false
            } else {
                if tcp_header.flags & TCP_SYN != 0 {
                    let mut new_stream = TcpStream::new(tcp_header.seq_num, 0);
                    if let Some(mss) = parse_tcp_options(&tcp_data[20..tcp_header_size]) {
                        new_stream.set_mss(true, mss);
                    }
                    streams.insert(stream_key, new_stream);
                }
                true
            };

            let stream_key = if is_from_client { stream_key } else { reverse_key };

            if let Some(stream) = streams.get_mut(&stream_key) {
                if tcp_header.flags & TCP_SYN != 0 && !is_from_client {
                    if let Some(mss) = parse_tcp_options(&tcp_data[20..tcp_header_size]) {
                        stream.set_mss(false, mss);
                    }
                }

                stream.update(
                    is_from_client,
                    tcp_header.seq_num,
                    tcp_header.ack_num,
                    tcp_header.flags,
                    payload,
                    tcp_header.window,
                );

                println!("Stream: {:?} -> {:?}", stream_key.0, stream_key.2);
                println!("State: {:?}", stream.state);
                println!("Client data: {} bytes", stream.client_data.len());
                println!("Server data: {} bytes", stream.server_data.len());
                println!("Client window: {}", stream.client_window);
                println!("Server window: {}", stream.server_window);
                println!("Client MSS: {}", stream.client_mss);
                println!("Server MSS: {}", stream.server_mss);
                println!("--------------------");
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device_list = Device::list()?;

    println!("利用可能なデバイス:");
    for (index, device) in device_list.iter().enumerate() {
        println!("{}. {}", index + 1, device.name);
        println!("   説明: {}", device.desc.as_deref().unwrap_or("説明なし"));
        println!("   アドレス: {:?}", device.addresses);
        println!();
    }

    print!("キャプチャするデバイスの番号を入力してください: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let device_index: usize = input.trim().parse()?;

    if device_index == 0 || device_index > device_list.len() {
        return Err("無効なデバイス番号です".into());
    }

    let selected_device = &device_list[device_index - 1];
    println!("選択されたデバイス: {}", selected_device.name);

    let mut cap = Capture::from_device(selected_device.clone())?
        .promisc(true)
        .snaplen(65535)
        .timeout(0)
        .immediate_mode(true)
        .buffer_size(3 * 1024 * 1024)
        .open()?;

    println!("パケットのキャプチャを開始します。Ctrl+Cで終了します。");

    let mut streams: HashMap<TcpStreamKey, TcpStream> = HashMap::new();

    while let Ok(packet) = cap.next_packet() {
        process_packet(&packet, &mut streams);

        // 古いストリームの削除
        streams.retain(|_, stream| {
            stream.last_activity.elapsed() < Duration::from_secs(300) || stream.state != TcpState::Closed
        });
    }

    Ok(())
}