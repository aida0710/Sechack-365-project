use pcap::{Device, Capture};

fn main() {
    // 利用可能なネットワークインターフェースを取得
    let devices = Device::list().expect("デバイスリストの取得に失敗しました");

    // 最初のデバイスを選択（実際の使用では、ユーザーに選択させるべきです）
    let device = &devices[0];
    println!("選択されたデバイス: {}", device.name);

    // キャプチャを開始
    let mut cap = Capture::from_device(device.clone())
        .unwrap()
        .promisc(true)
        .snaplen(5000)
        .open()
        .expect("キャプチャの開始に失敗しました");

    // パケットをキャプチャして表示
    while let Ok(packet) = cap.next_packet() {
        println!("パケットキャプチャ: {} bytes", packet.header.len);
        println!("キャプチャ時刻: {}.{:06} 秒", packet.header.ts.tv_sec, packet.header.ts.tv_usec);
        println!("パケットデータ: {:?}", packet.data);
        println!("------------------------");
    }
}