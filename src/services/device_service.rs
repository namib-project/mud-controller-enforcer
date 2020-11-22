use crate::models::mud_models::MUDData;
use std::net::IpAddr;

pub async fn get_all_devices() -> Vec<Device> {
    Vec::new()
}

pub struct Device {
    pub mud_url: String,
    pub mac: String,
    pub ip_address: IpAddr,
    pub mud_data: MUDData,
}
