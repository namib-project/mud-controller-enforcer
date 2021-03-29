#![allow(clippy::field_reassign_with_default)]

use crate::{
    error::Result,
    models::{Device, DeviceType, DeviceWithRefs, MudData, Room},
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
    pub clipart: Option<String>,
    pub room: Option<Room>,
    #[serde(rename = "type")]
    pub type_: DeviceType,
}

impl From<DeviceWithRefs> for DeviceDto {
    fn from(d: DeviceWithRefs) -> Self {
        let type_ = d.get_type();
        DeviceDto {
            id: d.id,
            ip_addr: d.ip_addr.to_string(),
            mac_addr: d.mac_addr.map(|m| m.to_string()),
            hostname: d.inner.hostname,
            vendor_class: d.inner.vendor_class,
            mud_url: d.inner.mud_url,
            last_interaction: d.inner.last_interaction,
            mud_data: d.mud_data,
            clipart: d.inner.clipart,
            room: d.room,
            type_,
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
    pub mud_url_from_guess: Option<bool>,
    pub last_interaction: Option<NaiveDateTime>,
    #[validate(length(max = 512))]
    pub clipart: Option<String>,
    pub room_id: Option<i64>,
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
            hostname: self.hostname.unwrap_or_else(|| "".to_string()),
            vendor_class: self.vendor_class.unwrap_or_else(|| "".to_string()),
            mud_url: self.mud_url,
            collect_info,
            last_interaction: Utc::now().naive_local(),
            clipart: self.clipart.clone(),
            room_id: self.room_id,
        })
    }

    pub fn merge(self, mut device: Device) -> Result<Device> {
        if self.mud_url.is_some() {
            device.mud_url = self.mud_url;
        }
        if let Some(hostname) = self.hostname {
            device.hostname = hostname;
        }
        if let Some(vendor_class) = self.vendor_class {
            device.vendor_class = vendor_class;
        }
        if let Some(room_id) = self.room_id {
            device.room_id = Some(room_id);
        }
        Ok(device)
    }
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct GuessDto {
    pub mud_url: String,
    pub model_name: Option<String>,
    pub manufacturer_name: Option<String>,
}
