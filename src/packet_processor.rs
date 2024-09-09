use crate::async_log_inserter::AsyncLogInserter;
use crate::ip_header::{parse_ip_header, IpHeader};
use crate::ip_reassembly::IpReassembler;
use crate::protocol_identifier::identify_protocol;
use crate::tcp_header::{parse_tcp_header, parse_tcp_options};
use crate::tcp_stream::{TcpStream, TcpStreamKey, TCP_SYN};
use chrono::{DateTime, Local};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

pub async fn process_packet(
    packet: &pcap::Packet,
    streams: &mut HashMap<TcpStreamKey, TcpStream>,
    ip_reassembler: &mut IpReassembler,
    inserter: Arc<AsyncLogInserter>,
) -> Result<(), Box<dyn std::error::Error>> {
    let arrival_time = SystemTime::now();
    let eth_header_size = 14; // Ethernetヘッダーのサイズ
    if packet.data.len() <= eth_header_size {
        return Ok(());
    }

    let ip_data = &packet.data[eth_header_size..];

    if let Some((ip_header, ip_header_size)) = parse_ip_header(ip_data) {
        let payload = &ip_data[ip_header_size..];

        // IPの再構築を試みる
        if let Some(reassembled_packet) = ip_reassembler.process_packet(&ip_header, payload) {
            // 再構築されたパケットを処理
            process_reassembled_packet(
                &ip_header,
                &reassembled_packet,
                streams,
                arrival_time,
                inserter.clone(),
            )
            .await?;
        } else {
            // フラグメントされていないパケットまたは再構築が完了していないパケットの処理
            process_tcp_packet(&ip_header, payload, streams, arrival_time, inserter.clone())
                .await?;
        }
    }

    // 定期的にクリーンアップを行う（例：100パケットごと）
    if packet.header.len % 100 == 0 {
        ip_reassembler.cleanup();
    }

    Ok(())
}

async fn process_reassembled_packet(
    ip_header: &IpHeader,
    packet: &[u8],
    streams: &mut HashMap<TcpStreamKey, TcpStream>,
    arrival_time: SystemTime,
    inserter: Arc<AsyncLogInserter>,
) -> Result<(), Box<dyn std::error::Error>> {
    if ip_header.protocol != 6 {
        // TCPのプロトコル番号は6
        return Ok(());
    }

    if let Some((tcp_header, tcp_header_size)) = parse_tcp_header(packet) {
        let payload = &packet[tcp_header_size..];
        process_tcp_data(
            ip_header,
            &tcp_header,
            payload,
            streams,
            arrival_time,
            inserter,
        )
        .await?;
    }

    Ok(())
}

async fn process_tcp_packet(
    ip_header: &IpHeader,
    tcp_data: &[u8],
    streams: &mut HashMap<TcpStreamKey, TcpStream>,
    arrival_time: SystemTime,
    inserter: Arc<AsyncLogInserter>,
) -> Result<(), Box<dyn std::error::Error>> {
    if ip_header.protocol != 6 {
        // TCPのプロトコル番号は6
        return Ok(());
    }

    if let Some((tcp_header, tcp_header_size)) = parse_tcp_header(tcp_data) {
        let payload = &tcp_data[tcp_header_size..];
        process_tcp_data(
            ip_header,
            &tcp_header,
            payload,
            streams,
            arrival_time,
            inserter,
        )
        .await?;
    }

    Ok(())
}

async fn process_tcp_data(
    ip_header: &IpHeader,
    tcp_header: &crate::tcp_header::TcpHeader,
    payload: &[u8],
    streams: &mut HashMap<TcpStreamKey, TcpStream>,
    arrival_time: SystemTime,
    inserter: Arc<AsyncLogInserter>,
) -> Result<(), Box<dyn std::error::Error>> {
    let stream_key = (
        ip_header.src_ip,
        tcp_header.src_port,
        ip_header.dst_ip,
        tcp_header.dst_port,
    );
    let reverse_key = (
        ip_header.dst_ip,
        tcp_header.dst_port,
        ip_header.src_ip,
        tcp_header.src_port,
    );

    let is_from_client = if streams.contains_key(&stream_key) {
        true
    } else if streams.contains_key(&reverse_key) {
        false
    } else {
        if tcp_header.flags & TCP_SYN != 0 {
            let mut new_stream = TcpStream::new(tcp_header.seq_num, 0);
            let options_end = (tcp_header.data_offset as usize * 4).saturating_sub(20);
            if payload.len() >= options_end {
                if let Some(mss) = parse_tcp_options(&payload[..options_end]) {
                    new_stream.set_mss(true, mss);
                }
            }
            streams.insert(stream_key, new_stream);
        }
        true
    };

    let stream_key = if is_from_client {
        stream_key
    } else {
        reverse_key
    };

    if let Some(stream) = streams.get_mut(&stream_key) {
        if tcp_header.flags & TCP_SYN != 0 && !is_from_client {
            let options_end = (tcp_header.data_offset as usize * 4).saturating_sub(20);
            if payload.len() >= options_end {
                if let Some(mss) = parse_tcp_options(&payload[..options_end]) {
                    stream.set_mss(false, mss);
                }
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

        stream.arrival_time = arrival_time;

        let protocol = identify_protocol(tcp_header.src_port, tcp_header.dst_port, payload);

        println!("Arrival time: {}", arrival_time_to_string(arrival_time));
        println!("Protocol: {:?}", protocol);
        println!(
            "Payload length: {}, TCP header data offset: {}",
            payload.len(),
            tcp_header.data_offset
        );
        println!(
            "Stream: {}:{} -> {}:{}",
            stream_key.0, tcp_header.src_port, stream_key.2, tcp_header.dst_port
        );
        println!("State: {:?}", stream.state);
        println!("Client data: {} bytes", stream.client_data.len());
        println!("Server data: {} bytes", stream.server_data.len());
        println!("Client window: {}", stream.client_window);
        println!("Server window: {}", stream.server_window);
        println!("Client MSS: {}", stream.client_mss);
        println!("Server MSS: {}", stream.server_mss);
        println!("Client CWND: {}", stream.client_cwnd);
        println!("Server CWND: {}", stream.server_cwnd);
        // establish状態のストリームのデータを表示
        if stream.state == crate::tcp_stream::TcpState::Established {
            if is_from_client {
                println!(
                    "Client data: {:?}",
                    String::from_utf8_lossy(&stream.client_data)
                );
            } else {
                println!(
                    "Server data: {:?}",
                    String::from_utf8_lossy(&stream.server_data)
                );
            }
        }
        println!("--------------------");

        // ストリームが閉じられたら残りのパケットデータを削除
        if stream.state == crate::tcp_stream::TcpState::Closed {
            streams.remove(&stream_key);
        }

        // パケットログのデータベースへの挿入
        inserter
            .insert(
                "packet_logs",
                &[
                    "arrival_time",
                    "protocol",
                    "src_ip",
                    "src_port",
                    "dst_ip",
                    "dst_port",
                    "payload_length",
                ],
                &[
                    &arrival_time_to_string(arrival_time),
                    &format!("{:?}", protocol),
                    &ip_header.src_ip.to_string(),
                    &tcp_header.src_port.to_string(),
                    &ip_header.dst_ip.to_string(),
                    &tcp_header.dst_port.to_string(),
                    &payload.len().to_string(),
                ],
            )
            .await?;
    }

    Ok(())
}

// SystemTimeを文字列に変換する
fn arrival_time_to_string(arrival_time: SystemTime) -> String {
    let datetime: DateTime<Local> = arrival_time.into();
    datetime.format("%Y-%m-%d %H:%M:%S.%3f %Z").to_string()
}
