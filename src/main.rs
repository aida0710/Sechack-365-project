use crate::select_device::select_device;
use crate::send_packet::send_packet_settings::send_packet_settings;
use dotenv::dotenv;
use pcap::{Active, Capture, Device};
mod packet_analysis;
mod send_packet;
mod select_device;

use pnet::packet::MutablePacket;
use std::error::Error;
use crate::packet_analysis::packet_analysis::packet_analysis;

fn main() -> Result<(), Box<dyn Error>> {
    // .envファイルを読み込む
    dotenv().ok();
    let (mut cap, device): (Capture<Active>, Device) = select_device()?;
    println!("デバイスの選択に成功しました: {}", device.name);

    // 不正なip パケットを送信
    if let Err(e) = send_packet_settings(&mut cap) {
        println!("不正なIPパケットの送信に失敗しました: {}", e);
    }

    // パケット解析
    /*if let Err(e) = packet_analysis(cap) {
        println!("パケットの解析に失敗しました: {}", e);
    }*/

    Ok(())
}