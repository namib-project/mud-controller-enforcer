use crate::{models::mud_models::MUDData, schema::*};
use chrono::{Local, NaiveDateTime};
use namib_shared::{mac_addr::macaddr, models::DhcpLeaseInformation, MacAddr};
use schemars::JsonSchema;
use std::net::IpAddr;

#[derive(Debug, Queryable, Identifiable, AsChangeset, Serialize, Deserialize, Clone)]
#[table_name = "devices"]
pub struct Device {
    pub id: i32,
    pub ip_addr: String,
    pub mac_addr: Option<String>,
    pub hostname: String,
    pub vendor_class: String,
    pub mud_url: Option<String>,
    pub last_interaction: NaiveDateTime,
}

impl From<&DeviceData> for Device {
    fn from(device_data: &DeviceData) -> Device {
        Device {
            id: device_data.id,
            ip_addr: device_data.ip_addr.to_string(),
            mac_addr: device_data.mac_addr.map(|m| m.to_string()),
            hostname: device_data.hostname.clone(),
            vendor_class: device_data.vendor_class.clone(),
            mud_url: device_data.mud_url.clone(),
            last_interaction: device_data.last_interaction,
        }
    }
}

#[derive(Debug, Insertable)]
#[table_name = "devices"]
pub struct InsertableDevice {
    pub ip_addr: String,
    pub mac_addr: Option<String>,
    pub hostname: String,
    pub vendor_class: String,
    pub mud_url: Option<String>,
    pub last_interaction: NaiveDateTime,
}

impl From<&DeviceData> for InsertableDevice {
    fn from(device_data: &DeviceData) -> Self {
        InsertableDevice {
            ip_addr: device_data.ip_addr.to_string(),
            mac_addr: device_data.mac_addr.map(|m| m.to_string()),
            hostname: device_data.hostname.clone(),
            vendor_class: device_data.vendor_class.clone(),
            mud_url: device_data.mud_url.clone(),
            last_interaction: device_data.last_interaction,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct DeviceData {
    pub id: i32,
    pub ip_addr: IpAddr,
    pub mac_addr: Option<MacAddr>,
    pub hostname: String,
    pub vendor_class: String,
    pub mud_url: Option<String>,
    pub last_interaction: NaiveDateTime,
    pub mud_data: Option<MUDData>,
}

impl From<Device> for DeviceData {
    fn from(device: Device) -> DeviceData {
        DeviceData {
            id: device.id,
            ip_addr: device.ip_addr.parse::<IpAddr>().expect("Is valid ip addr"),
            mac_addr: device.mac_addr.map(|m| m.parse::<macaddr::MacAddr>().expect("Is valid mac addr").into()),
            hostname: device.hostname,
            vendor_class: device.vendor_class,
            mud_url: device.mud_url,
            last_interaction: device.last_interaction,
            mud_data: None,
        }
    }
}

impl From<DhcpLeaseInformation> for DeviceData {
    fn from(lease_info: DhcpLeaseInformation) -> Self {
        DeviceData {
            id: 0,
            mac_addr: lease_info.mac_address,
            ip_addr: lease_info.ip_addr(),
            hostname: lease_info.old_hostname.unwrap_or_default(),
            vendor_class: "".to_string(),
            mud_url: lease_info.mud_url,
            last_interaction: Local::now().naive_local(),
            mud_data: None,
        }
    }
}
