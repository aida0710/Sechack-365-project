use pcap::Device;
use crate::error::Result;

pub fn get_available_devices() -> Result<Vec<Device>> {
    Device::list().map_err(Into::into)
}