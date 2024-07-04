use pcap::{Capture, Device};

pub fn packet_capture(capture_device: Device) -> Result<(), Box<dyn std::error::Error>> {
    let mut cap = Capture::from_device(capture_device)?
        .promisc(true)
        .snaplen(65535)
        .open()?;

    let mut save_file = cap.savefile("capture.pcap")?;
    println!("パケットキャプチャを開始します...");
    let mut count = 0;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                println!("パケット #{}: {:?}", count, packet);
                save_file.write(&packet);
                
                if count >= 100 {
                    break;
                }
                count += 1;
            },
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }

    save_file.flush()?;

    Ok(())
}