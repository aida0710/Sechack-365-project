use crate::select_device::select_device;
use dotenv::dotenv;
use pcap::{Active, Capture, Device};
mod packet_analysis;
mod select_device;
mod ip_header;
mod ip_reassembly;
mod packet_processor;
mod tcp_header;
mod tcp_stream;

use crate::packet_analysis::packet_analysis;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // .envファイルを読み込む
    dotenv().ok();
    let (cap, device): (Capture<Active>, Device) = select_device()?;
    println!("デバイスの選択に成功しました: {}", device.name);

    if let Err(e) = packet_analysis(cap) {
        println!("パケットの解析に失敗しました: {}", e);
    }

    Ok(())
}