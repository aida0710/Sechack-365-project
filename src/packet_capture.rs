use pcap::{Capture, Device};

pub fn packet_capture(capture_device: Device) -> Result<(), Box<dyn std::error::Error>> {
    let mut cap = Capture::from_device(capture_device)?
        .promisc(true) // プロミスキャスモードを有効にする(自分宛以外のパケットもキャプチャする)
        .snaplen(65535) // キャプチャするパケットの最大サイズを指定(65535バイトはEthernetフレームの最大サイズなので、実質無制限)
        .buffer_size(5 * 1024 * 1024) // バッファサイズを5MBに指定
        .immediate_mode(true) // キャプチャを開始するとすぐにパケットを取得する
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