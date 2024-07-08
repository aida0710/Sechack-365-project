use pcap::Capture;
use crate::packet_parser::parse_packet;
use crate::app::App;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub fn start_packet_capture(app: Arc<Mutex<App>>) -> Result<(), Box<dyn std::error::Error>> {
    let mut current_device: Option<String> = None;

    loop {
        thread::sleep(Duration::from_millis(100));
        let (device, is_capturing, device_changed) = {
            let mut app = app.lock().unwrap();
            let device = app.selected_device.clone();
            let is_capturing = app.is_capturing;
            let device_changed = app.device_changed;
            app.device_changed = false;
            (device, is_capturing, device_changed)
        };

        if !is_capturing {
            current_device = None;
            continue;
        }

        if let Some(device) = device {
            if current_device.as_ref() != Some(&device.name) || device_changed {
                current_device = Some(device.name.clone());

                let mut cap = Capture::from_device(device.clone())?
                    .promisc(true)
                    .snaplen(65535)
                    .timeout(100)
                    .buffer_size(2 * 1024 * 1024)
                    .immediate_mode(true)
                    .open()?;

                loop {
                    let (is_capturing, device_name) = {
                        let app = app.lock().unwrap();
                        (app.is_capturing, app.selected_device.as_ref().map(|d| d.name.clone()))
                    };

                    if !is_capturing || device_name.as_ref() != Some(&device.name) {
                        break;
                    }

                    match cap.next_packet() {
                        Ok(packet) => {
                            if let Some((src_ip, dst_ip, protocol, src_port, dst_port)) = parse_packet(&packet.data) {
                                let packet_info = format!("{}:{} > {}:{} {}",
                                                          src_ip, src_port, dst_ip, dst_port, protocol);
                                let mut app = app.lock().unwrap();
                                app.add_captured_packet(packet_info);
                            }
                        }
                        Err(pcap::Error::TimeoutExpired) => {
                            continue;
                        }
                        Err(e) => {
                            eprintln!("Error capturing packet: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    }
}