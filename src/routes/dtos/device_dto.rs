#![allow(clippy::field_reassign_with_default)]

use crate::{
    error::Result,
    models::{Device, MudData},
};
use chrono::{Local, NaiveDateTime};
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
    pub clipart: Option<String>,
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
            clipart: d.clipart,
        }
    }
}

#[derive(Validate, Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct DeviceCreationUpdateDto {
    pub ip_addr: String,
    pub mac_addr: Option<String>,
    pub hostname: Option<String>,
    pub vendor_class: Option<String>,
    pub mud_url: Option<String>,
    pub last_interaction: Option<NaiveDateTime>,
    #[validate(length(max = 512))]
    pub clipart: Option<String>,
}

impl DeviceCreationUpdateDto {
    pub fn to_device(&self, id: i64, collect_info: bool) -> Result<Device> {
        let mac_addr = match self.mac_addr.clone() {
            None => None,
            Some(m) => Some(MacAddr::from(m.parse::<mac::MacAddr>()?)),
        };
        let ip_addr = self.ip_addr.clone().parse::<std::net::IpAddr>()?;

        Ok(Device {
            id,
            mac_addr,
            ip_addr,
            hostname: self.hostname.clone().unwrap_or("".to_string()),
            vendor_class: self.vendor_class.clone().unwrap_or("".to_string()),
            mud_url: self.mud_url.clone(),
            collect_info,
            last_interaction: Local::now().naive_local(),
            mud_data: None,
            clipart: self.clipart.clone(),
        })
    }
}
