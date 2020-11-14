use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Serialize, Deserialize, Debug)]
pub struct DHCPRequestData {
    pub ip_addr: IpAddr,
    pub mac_addr: [u8; 8],
    pub mud_url: String,
    pub hostname: String,
    pub vendor_class: String,
    pub request_timestamp: std::time::SystemTime,
}
