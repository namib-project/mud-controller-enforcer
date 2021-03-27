use crate::models::mud_models::MudData;
use chrono::{NaiveDateTime, Utc};
use namib_shared::{
    mac,
    models::{DhcpLeaseInformation, DhcpLeaseVersionSpecificInformation},
    MacAddr,
};
use paperclip::actix::Apiv2Schema;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct DeviceDbo {
    pub id: i64,
    pub name: Option<String>,
    pub ipv4_addr: Option<String>,
    pub ipv6_addr: Option<String>,
    pub mac_addr: Option<String>,
    pub duid: Option<String>,
    pub hostname: String,
    pub vendor_class: String,
    pub mud_url: Option<String>,
    pub collect_info: bool,
    pub last_interaction: NaiveDateTime,
    pub clipart: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Device {
    pub id: i64,
    pub name: Option<String>,
    pub ipv4_addr: Option<Ipv4Addr>,
    pub ipv6_addr: Option<Ipv6Addr>,
    pub mac_addr: Option<MacAddr>,
    pub duid: Option<String>,
    pub hostname: String,
    pub vendor_class: String,
    pub mud_url: Option<String>,
    pub collect_info: bool,
    pub last_interaction: NaiveDateTime,
    pub mud_data: Option<MudData>,
    pub clipart: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
#[serde(rename_all = "snake_case")]
pub enum DeviceType {
    Managed,
    Detecting,
    Unknown,
}

impl Device {
    pub fn get_type(&self) -> DeviceType {
        if self.mud_url.is_some() {
            DeviceType::Managed
        } else if self.collect_info {
            DeviceType::Detecting
        } else {
            DeviceType::Unknown
        }
    }
}

impl From<DeviceDbo> for Device {
    fn from(device: DeviceDbo) -> Self {
        Self {
            id: device.id,
            name: device.name,
            ipv4_addr: device.ipv4_addr.and_then(|ip| ip.parse().ok()),
            ipv6_addr: device.ipv6_addr.and_then(|ip| ip.parse().ok()),
            mac_addr: device
                .mac_addr
                .map(|m| m.parse::<mac::MacAddr>().expect("Is valid mac addr").into()),
            duid: device.duid,
            hostname: device.hostname,
            vendor_class: device.vendor_class,
            mud_url: device.mud_url,
            mud_data: None,
            collect_info: device.collect_info,
            last_interaction: device.last_interaction,
            clipart: device.clipart,
        }
    }
}

impl Device {
    pub fn new(lease_info: DhcpLeaseInformation) -> Self {
        Self {
            id: 0,
            name: None,
            mac_addr: lease_info.mac_address,
            ipv4_addr: if let IpAddr::V4(addr) = lease_info.ip_addr() {
                Some(addr)
            } else {
                None
            },
            ipv6_addr: if let IpAddr::V6(addr) = lease_info.ip_addr() {
                Some(addr)
            } else {
                None
            },
            duid: if let DhcpLeaseVersionSpecificInformation::V6(info) = lease_info.version_specific_information {
                Some(info.duid.to_string())
            } else {
                None
            },
            hostname: lease_info.hostname.unwrap_or_default(),
            vendor_class: "".to_string(),
            mud_url: lease_info.mud_url,
            collect_info: false,
            last_interaction: Utc::now().naive_utc(),
            mud_data: None,
            clipart: None,
        }
    }

    pub fn mac_or_duid(&self) -> String {
        self.mac_addr
            .map(|m| m.to_string())
            .or_else(|| self.duid.as_ref().cloned())
            .unwrap()
    }

    pub fn apply(&mut self, lease_info: DhcpLeaseInformation) {
        if let IpAddr::V4(ip) = lease_info.ip_addr() {
            self.ipv4_addr = Some(ip);
        } else if let IpAddr::V6(ip) = lease_info.ip_addr() {
            self.ipv6_addr = Some(ip);
        }
        if let Some(mac) = lease_info.mac_address {
            self.mac_addr = Some(mac);
        }
        if let DhcpLeaseVersionSpecificInformation::V6(info) = lease_info.version_specific_information {
            self.duid = Some(info.duid.to_string());
        }
        if let Some(hostname) = lease_info.hostname {
            self.hostname = hostname;
        }
        if self.mud_url.is_none() && lease_info.mud_url.is_some() {
            self.mud_url = lease_info.mud_url;
        }
    }
}
