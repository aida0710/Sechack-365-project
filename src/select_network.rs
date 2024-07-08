use pcap::Device;

pub fn get_available_devices() -> Result<Vec<Device>, Box<dyn std::error::Error>> {
    Ok(Device::list()?)
}