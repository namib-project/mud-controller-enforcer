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
    pub name: Option<String>,
    pub ipv4_addr: Option<String>,
    pub ipv6_addr: Option<String>,
    pub mac_addr: Option<String>,
    pub duid: Option<String>,
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
            name: d.name,
            ipv4_addr: d.ipv4_addr.map(|ip| ip.to_string()),
            ipv6_addr: d.ipv6_addr.map(|ip| ip.to_string()),
            mac_addr: d.mac_addr.map(|m| m.to_string()),
            duid: d.duid,
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
    pub name: Option<String>,
    pub ipv4_addr: Option<String>,
    pub ipv6_addr: Option<String>,
    pub mac_addr: Option<String>,
    pub duid: Option<String>,
    pub hostname: Option<String>,
    pub vendor_class: Option<String>,
    pub mud_url: Option<String>,
    pub mud_url_from_guess: Option<bool>,
    pub last_interaction: Option<NaiveDateTime>,
    #[validate(length(max = 512))]
    pub clipart: Option<String>,
}

impl DeviceCreationUpdateDto {
    pub fn apply_to(self, device: &mut Device) {
        if self.mud_url.is_some() {
            device.mud_url = self.mud_url;
            device.mud_data = None;
        }
        if let Some(hostname) = self.hostname {
            device.hostname = hostname;
        }
        if let Some(vendor_class) = self.vendor_class {
            device.vendor_class = vendor_class;
        }
    }
}

impl Into<Device> for DeviceCreationUpdateDto {
    fn into(self) -> Device {
        Device {
            id: 0,
            name: self.name,
            ipv4_addr: self.ipv4_addr.and_then(|ip| ip.parse().ok()),
            ipv6_addr: self.ipv6_addr.and_then(|ip| ip.parse().ok()),
            mac_addr: self
                .mac_addr
                .and_then(|m| m.parse::<mac::MacAddr>().ok())
                .map(|m| m.into()),
            duid: self.duid,
            hostname: self.hostname.unwrap_or_default(),
            vendor_class: self.vendor_class.unwrap_or_default(),
            mud_url: self.mud_url,
            mud_data: None,
            collect_info: false,
            last_interaction: Utc::now().naive_local(),
            clipart: self.clipart.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct GuessDto {
    pub mud_url: String,
    pub model_name: Option<String>,
    pub manufacturer_name: Option<String>,
}
