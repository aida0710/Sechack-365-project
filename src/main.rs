use std::collections::HashMap;
use std::io::{self, Write};
use std::time::Duration;

use pcap::{Capture, Device};
use dotenv::dotenv;

mod tcp_stream;
mod ip_header;
mod tcp_header;
mod packet_processor;
mod ip_reassembly;

use ip_reassembly::IpReassembler;
use packet_processor::process_packet;
use tcp_stream::TcpStream;
use tcp_stream::TcpStreamKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // .envファイルを読み込む
    dotenv().ok();

    let device_list = Device::list()?;

    println!("利用可能なデバイス:");
    for (index, device) in device_list.iter().enumerate() {
        println!("{}. {}", index + 1, device.name);
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
    let mut ip_reassembler = IpReassembler::new(Duration::from_secs(30));

    while let Ok(packet) = cap.next_packet() {
        match process_packet(&packet, &mut streams, &mut ip_reassembler){
            Ok(_) => (),
            Err(e) => eprintln!("パケット処理中にエラーが発生しました: {}", e),
        }

        // 古いストリームの削除
        streams.retain(|_, stream| {
            stream.last_activity.elapsed() < Duration::from_secs(300) || stream.state != tcp_stream::TcpState::Closed
        });
    }

    Ok(())
}