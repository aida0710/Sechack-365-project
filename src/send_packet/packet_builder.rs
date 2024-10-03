use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::MutablePacket;
use pnet::util::MacAddr;
use std::error::Error;

use super::settings::SendPacketSettings;

pub fn build_packet(settings: &SendPacketSettings) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut ethernet_buffer = vec![0u8; 14 + 20 + 20 + settings.payload.len()];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(MacAddr::new(0, 0, 0, 0, 0, 0));
    ethernet_packet.set_source(MacAddr::new(0, 0, 0, 0, 0, 0));
    ethernet_packet.set_ethertype(EtherTypes::Ipv4);

    let mut ipv4_packet = MutableIpv4Packet::new(ethernet_packet.payload_mut()).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length((20 + 20 + settings.payload.len()) as u16);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ipv4_packet.set_source(settings.src_ip);
    ipv4_packet.set_destination(settings.dst_ip);

    let mut tcp_packet = MutableTcpPacket::new(ipv4_packet.payload_mut()).unwrap();
    tcp_packet.set_source(settings.src_port);
    tcp_packet.set_destination(settings.dst_port);
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(64240);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_payload(&settings.payload);

    Ok(ethernet_buffer)
}