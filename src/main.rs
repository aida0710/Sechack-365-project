use pcap::{Device, Capture, Active};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 利用可能なネットワークインターフェースを取得
    let devices: Vec<Device> = Device::list()?;

    // 最初のデバイスを選択
    let device: &Device = devices.first().ok_or("No devices found")?;
    println!("選択されたデバイス: {}", device.name);

    // キャプチャを開始
    let mut cap: Capture<Active> = Capture::from_device(device.clone())?
        .promisc(true)
        .snaplen(5000)
        .open()
        .expect("キャプチャの開始に失敗しました");

    println!("パケットキャプチャを開始します...");

    // パケットをキャプチャして表示
    while let Ok(packet) = cap.next_packet() {
        println!("パケットキャプチャ: {} bytes", packet.header.len);
        println!("キャプチャ時刻: {}.{:06} 秒", packet.header.ts.tv_sec, packet.header.ts.tv_usec);
        //println!("パケットデータ: {:?}", packet.data);
        println!("------------------------");
    }

    Ok(())
}