use crate::select_device::select_device;
use dotenv::dotenv;
use pcap::{Active, Capture, Device};
mod packet_analysis;
mod send_packet;
mod select_device;

use pnet::packet::MutablePacket;
use std::error::Error;
use crate::send_packet::{packet_sender, SettingsPattern};

fn main() -> Result<(), Box<dyn Error>> {
    // .envファイルを読み込む
    dotenv().ok();
    let (mut cap, device): (Capture<Active>, Device) = select_device()?;
    println!("デバイスの選択に成功しました: {}", device.name);

    // デフォルトパターンを使用
    packet_sender(&mut cap, SettingsPattern::Attack)?;

    // パケット解析
    /*if let Err(e) = packet_analysis(cap) {
        println!("パケットの解析に失敗しました: {}", e);
    }*/

    Ok(())
}