use std::io;
use pcap::Device;
use std::io::Write;

// ネットワークインターフェースを選択し、そのインターフェースを返す
pub fn select_network_interface() -> Result<Device, Box<dyn std::error::Error>> {
    let devices: Vec<Device> = Device::list()?;

    println!("利用可能なデバイス:");
    for (i, device) in devices.iter().enumerate() {
        println!("{}. {}", i + 1, device.name);
    }
    print!("使用するデバイスの番号を入力してください: ");

    // バッファをフラッシュしてから入力を受け付ける
    io::stdout().flush()?;
    let mut input: String = String::new();
    io::stdin().read_line(&mut input)?;

    // デバイス番号を取得
    let device_index: usize = input.trim().parse::<usize>()? - 1;
    let device: &Device = devices.get(device_index).ok_or("無効なデバイス番号")?;

    println!("選択されたデバイス: {}", device.name);

    Ok(device.clone())
}