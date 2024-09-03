use std::collections::HashMap;
use crate::tcp_stream::{TcpStream, TcpStreamKey, TCP_SYN};
use crate::ip_header::parse_ip_header;
use crate::tcp_header::{parse_tcp_header, parse_tcp_options};

pub fn process_packet(packet: &pcap::Packet, streams: &mut HashMap<TcpStreamKey, TcpStream>) {
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