#![allow(clippy::field_reassign_with_default)]

use crate::{
    error::Result,
    models::{Device, MudData},
};
use chrono::{NaiveDateTime, Utc};
use namib_shared::{mac, MacAddr};
use paperclip::actix::Apiv2Schema;

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct DeviceDto {
    pub id: i64,
    pub ip_addr: String,
    pub mac_addr: Option<String>,
    pub hostname: String,
    pub vendor_class: String,
    pub mud_url: Option<String>,
    pub last_interaction: NaiveDateTime,
    pub mud_data: Option<MudData>,
}

impl From<Device> for DeviceDto {
    fn from(d: Device) -> Self {
        DeviceDto {
            id: d.id,
            ip_addr: d.ip_addr.to_string(),
            mac_addr: d.mac_addr.map(|m| m.to_string()),
            hostname: d.hostname,
            vendor_class: d.vendor_class,
            mud_url: d.mud_url,
            last_interaction: d.last_interaction,
            mud_data: d.mud_data,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct DeviceCreationUpdateDto {
    pub ip_addr: String,
    pub mac_addr: Option<String>,
    pub hostname: Option<String>,
    pub vendor_class: Option<String>,
    pub mud_url: Option<String>,
    pub last_interaction: Option<NaiveDateTime>,
}

impl DeviceCreationUpdateDto {
    pub fn into_device(self, collect_info: bool) -> Result<Device> {
        let mac_addr = match self.mac_addr {
            None => None,
            Some(m) => Some(MacAddr::from(m.parse::<mac::MacAddr>()?)),
        };
        let ip_addr = self.ip_addr.parse::<std::net::IpAddr>()?;

        Ok(Device {
            id: 0,
            mac_addr,
            ip_addr,
            hostname: self.hostname.unwrap_or("".to_string()),
            vendor_class: self.vendor_class.unwrap_or("".to_string()),
            mud_url: self.mud_url,
            collect_info,
            last_interaction: Utc::now().naive_local(),
            mud_data: None,
        })
    }

    pub fn merge(self, mut device: Device) -> Result<Device> {
        let mac_addr = match self.mac_addr {
            None => None,
            Some(m) => Some(MacAddr::from(m.parse::<mac::MacAddr>()?)),
        };
        let ip_addr = self.ip_addr.parse::<std::net::IpAddr>()?;
        device.mac_addr = mac_addr;
        device.ip_addr = ip_addr;
        device.mud_url = self.mud_url;
        device.mud_data = None;
        Ok(device)
    }
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct GuessDto {
    pub mud_url: String,
    pub model_name: Option<String>,
    pub manufacturer_name: Option<String>,
}
