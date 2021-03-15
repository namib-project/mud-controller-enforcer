use crate::models::mud_models::MudData;
use chrono::{Local, NaiveDateTime};
use namib_shared::{mac, models::DhcpLeaseInformation, MacAddr};
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct DeviceDbo {
    pub id: i64,
    pub ip_addr: String,
    pub mac_addr: Option<String>,
    pub hostname: String,
    pub vendor_class: String,
    pub mud_url: Option<String>,
    pub collect_info: bool,
    pub last_interaction: NaiveDateTime,
}

#[derive(Debug, Clone)]
pub struct Device {
    pub id: i64,
    pub ip_addr: IpAddr,
    pub mac_addr: Option<MacAddr>,
    pub hostname: String,
    pub vendor_class: String,
    pub mud_url: Option<String>,
    pub collect_info: bool,
    pub last_interaction: NaiveDateTime,
    pub mud_data: Option<MudData>,
}

impl From<DeviceDbo> for Device {
    fn from(device: DeviceDbo) -> Device {
        Device {
            id: device.id,
            ip_addr: device.ip_addr.parse::<std::net::IpAddr>().expect("Is valid ip addr"),
            mac_addr: device
                .mac_addr
                .map(|m| m.parse::<mac::MacAddr>().expect("Is valid mac addr").into()),
            hostname: device.hostname,
            vendor_class: device.vendor_class,
            mud_url: device.mud_url,
            collect_info: device.collect_info,
            last_interaction: device.last_interaction,
            mud_data: None,
        }
    }
}

impl From<DhcpLeaseInformation> for Device {
    fn from(lease_info: DhcpLeaseInformation) -> Self {
        Device {
            id: 0,
            mac_addr: lease_info.mac_address,
            ip_addr: lease_info.ip_addr(),
            hostname: lease_info.hostname.unwrap_or_default(),
            vendor_class: "".to_string(),
            mud_url: lease_info.mud_url,
            collect_info: false,
            last_interaction: Local::now().naive_local(),
            mud_data: None,
        }
    }
}
