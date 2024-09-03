use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::time::Instant;

use pcap::{Capture, Device};

// TCPフラグの定義
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

// TCPセッションの状態を表す列挙型
#[derive(Debug, PartialEq)]
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
}

// IPヘッダーの構造
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
fn parse_ip_header(data: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, usize, bool)> {
    if data.len() < 20 {
        return None;
    }

    let version = (data[0] >> 4) & 0xF;
    if version != 4 {
        return None;  // IPv4のみをサポート
    }

    let ihl = (data[0] & 0xF) as usize * 4;
    let _total_length = u16::from_be_bytes([data[2], data[3]]) as usize;
    let more_fragments = (data[6] & 0x20) != 0;
    let fragment_offset = u16::from_be_bytes([data[6] & 0x1F, data[7]]) as usize * 8;
    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    Some((src_ip, dst_ip, ihl, more_fragments || fragment_offset > 0))
}

// TCPヘッダーの構造
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
fn parse_tcp_header(data: &[u8]) -> Option<TcpHeader> {
    if data.len() < 20 {
        return None;
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]); //2byte (16bit)
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]); //4byte (32bit)
    let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    let data_offset = (data[12] >> 4) & 0xF;
    let reserved = (data[12] & 0xF) << 2 | (data[13] >> 6);
    let flags = data[13] & 0x3F;
    let window = u16::from_be_bytes([data[14], data[15]]);

    Some(TcpHeader {
        src_port,
        dst_port,
        seq_num,
        ack_num,
        data_offset,
        reserved,
        flags,
        window,
    })
}

struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    data_offset: u8,
    reserved: u8,
    flags: u8,
    window: u16,
}

// パケットを処理する関数
fn process_packet(packet: &pcap::Packet) {
    let ip_data = &packet.data[14..];

    if let Some((src_ip, dst_ip, ip_header_size, is_fragment)) = parse_ip_header(ip_data) {
        if is_fragment {
            return;
        }

        let tcp_data = &ip_data[ip_header_size..];
        match parse_tcp_header(tcp_data) {
            Some(tcp_header) => {
                println!("Packet: {}:{} -> {}:{}, seq={}, ack={}, data_offset={}, reserved={}, flags=0x{:02X}, window={}, data_len={}",
                         src_ip, tcp_header.src_port, dst_ip, tcp_header.dst_port,
                         tcp_header.seq_num, tcp_header.ack_num, tcp_header.data_offset, tcp_header.reserved,
                         tcp_header.flags, tcp_header.window, tcp_data.len() - tcp_header.data_offset as usize * 4);
            }
            None => {
                println!("non tcp packets")
            }
        }
    } else {
        println!("non ip packets");
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 利用可能なネットワークインターフェース（ネットワークカード）の一覧を取得
    let device_list = Device::list()?;

    println!("利用可能なデバイス:");
    for (index, device) in device_list.iter().enumerate() {
        println!("{}. {}", index + 1, device.name);
        println!("   説明: {}", device.desc.as_deref().unwrap_or("説明なし"));
        println!("   アドレス: {:?}", device.addresses);
        println!();
    }

    // ユーザーにデバイスを選択してもらう
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

    // パケットのキャプチャを開始
    let mut cap = Capture::from_device(selected_device.clone())?
        .promisc(true)
        .snaplen(65535)
        .timeout(0)
        .immediate_mode(true)
        .buffer_size(3 * 1024 * 1024)
        .open()?;

    println!("パケットのキャプチャを開始します。Ctrl+Cで終了します。");

    // パケットをキャプチャして処理するループ
    while let Ok(packet) = cap.next_packet() {
        process_packet(&packet);
    }

    Ok(())
}