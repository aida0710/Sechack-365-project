use std::net::Ipv4Addr;
use pcap::{Device, Capture, Active};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::datalink::MacAddr;
use pnet::packet::{MutablePacket, Packet};

pub fn send_notice_packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16, payload: String) -> bool {
    // Find the default network interface
    let interface = Device::lookup().unwrap().unwrap();

    // Open the interface in promiscuous mode
    let mut cap = Capture::from_device(interface).unwrap()
        .promisc(true)
        .snaplen(65535)
        .open().unwrap();

    // Construct the Ethernet frame
    let mut ethernet_buffer = [0u8; 42 + 1460]; // Ethernet header + IP header + TCP header + max payload
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(MacAddr::zero()); // Replace with actual MAC address
    ethernet_packet.set_ethertype(EtherTypes::Ipv4);

    // Construct the IP packet
    let mut ip_packet = MutableIpv4Packet::new(ethernet_packet.payload_mut()).unwrap();

    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length(20 + 20 + payload.len() as u16);
    ip_packet.set_ttl(64);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_packet.set_source(src_ip);
    ip_packet.set_destination(dst_ip);

    // Construct the TCP packet
    let mut tcp_packet = MutableTcpPacket::new(ip_packet.payload_mut()).unwrap();

    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
    tcp_packet.set_sequence(0);
    tcp_packet.set_acknowledgement(0);
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(64240);
    tcp_packet.set_data_offset(5);

    // Set the payload
    tcp_packet.set_payload(payload.as_bytes());

    // Send the packet
    match cap.sendpacket(&ethernet_packet.packet()) {
        Ok(_) => true,
        Err(_) => false,
    }
}