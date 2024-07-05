mod send_notice_packet;
mod app;
mod select_network;
mod packet_capture;
mod packet_parser;
mod port_to_protocol;

use pcap::Device;
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device: Device = select_network::select_network_interface()?;
    packet_capture::packet_capture(device.clone())?;

    Ok(())
}

