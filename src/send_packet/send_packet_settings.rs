use pcap::{Active, Capture};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::MutablePacket;
use pnet::util::MacAddr;
use std::error::Error;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

pub struct SendPacketSettings {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    packet_size: usize,
    packet_count: usize,
    interval: Duration,
    timeout: Duration,
    payload: Vec<u8>,
}

impl SendPacketSettings {
    pub fn default() -> Self {
        Self {
            src_ip: "1.1.1.1".parse().unwrap(),
            dst_ip: "3.3.3.3".parse().unwrap(),
            src_port: 50000,
            dst_port: 50000,
            packet_size: 1000,
            packet_count: 1000,
            interval: Duration::from_millis(1),
            timeout: Duration::from_secs(10),
            payload: vec![0; 1000],
        }
    }

    fn set_src_ip(&mut self, src_ip: Ipv4Addr) {
        self.src_ip = src_ip;
    }

    fn set_dst_ip(&mut self, dst_ip: Ipv4Addr) {
        self.dst_ip = dst_ip;
    }

    fn set_src_port(&mut self, src_port: u16) {
        self.src_port = src_port;
    }

    fn set_dst_port(&mut self, dst_port: u16) {
        self.dst_port = dst_port;
    }

    fn set_packet_size(&mut self, packet_size: usize) {
        self.packet_size = packet_size;
    }

    fn set_packet_count(&mut self, packet_count: usize) {
        self.packet_count = packet_count;
    }

    fn set_interval(&mut self, interval: Duration) {
        self.interval = interval;
    }

    fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    fn set_payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }

    fn get_src_ip(&self) -> Ipv4Addr {
        self.src_ip
    }
}

pub fn send_packet_settings(cap: &mut Capture<Active>) -> Result<(), Box<dyn Error>> {
    let settings = SendPacketSettings::default();

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

    println!("パケット送信を開始します...");
    let start_time = Instant::now();

    for i in 0..settings.packet_count {
        cap.sendpacket(ethernet_buffer.clone())?;
        println!("パケット {} / {} を送信しました", i + 1, settings.packet_count);
        std::thread::sleep(settings.interval);
    }

    let elapsed_time = start_time.elapsed();
    println!("パケット送信が完了しました");
    println!("総送信パケット数: {}", settings.packet_count);
    println!("経過時間: {:.2} 秒", elapsed_time.as_secs_f64());

    Ok(())
}
