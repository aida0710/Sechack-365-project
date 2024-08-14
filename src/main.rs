use pcap::Device;

fn main() {
    let device_list = Device::list();
    match device_list {
        Ok(devices) => {
            for device in devices {
                println!("Device name: {}", device.name);
                println!(
                    "Device description: {}",
                    device.desc.unwrap_or("No description".to_string())
                );
                println!("Device addresses: {:?}", device.addresses);
                println!();
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
}
