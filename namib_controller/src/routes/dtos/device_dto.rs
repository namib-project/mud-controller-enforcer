// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::field_reassign_with_default)]

use chrono::{NaiveDateTime, Utc};
use namib_shared::macaddr::{MacAddr, SerdeMacAddr};
use paperclip::actix::Apiv2Schema;

use crate::{
    error::Result,
    models::{Device, DeviceType, DeviceWithRefs, MudData, Room},
};

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
    pub room: Option<Room>,
    pub q_bit: bool,
    #[serde(rename = "type")]
    pub type_: DeviceType,
}

impl From<DeviceWithRefs> for DeviceDto {
    fn from(d: DeviceWithRefs) -> Self {
        let type_ = d.get_type();
        DeviceDto {
            id: d.id,
            ipv4_addr: d.ipv4_addr.map(|ip| ip.to_string()),
            ipv6_addr: d.ipv6_addr.map(|ip| ip.to_string()),
            mac_addr: d.mac_addr.map(|m| m.to_string()),
            name: d.inner.name,
            duid: d.inner.duid,
            hostname: d.inner.hostname,
            vendor_class: d.inner.vendor_class,
            mud_url: d.inner.mud_url,
            last_interaction: d.inner.last_interaction,
            mud_data: d.mud_data,
            clipart: d.inner.clipart,
            room: d.room,
            q_bit: d.inner.q_bit,
            type_,
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
    #[validate(length(max = 512))]
    pub clipart: Option<String>,
    pub room_id: Option<i64>,
    pub collect_info: Option<bool>,
    pub q_bit: Option<bool>,
}

impl DeviceCreationUpdateDto {
    pub fn into_device(self, collect_info: bool) -> Result<Device> {
        let mac_addr = match self.mac_addr {
            None => None,
            Some(m) => Some(SerdeMacAddr::from(m.parse::<MacAddr>()?)),
        };

        Ok(Device {
            id: 0,
            name: None,
            mac_addr,
            duid: self.duid,
            ipv4_addr: self.ipv4_addr.and_then(|ip| ip.parse().ok()),
            ipv6_addr: self.ipv6_addr.and_then(|ip| ip.parse().ok()),
            hostname: self.hostname.unwrap_or_else(|| "".to_string()),
            vendor_class: self.vendor_class.unwrap_or_else(|| "".to_string()),
            mud_url: self.mud_url,
            collect_info: self.collect_info.unwrap_or(collect_info),
            last_interaction: Utc::now().naive_utc(),
            clipart: self.clipart.clone(),
            room_id: self.room_id,
            q_bit: self.q_bit.unwrap_or(false),
        })
    }

    pub fn apply_to(self, device: &mut Device) {
        if let Some(name) = self.name {
            device.name = Some(name);
        }
        if let Some(v4) = self.ipv4_addr {
            device.ipv4_addr = v4.parse().ok();
        }
        if let Some(v6) = self.ipv6_addr {
            device.ipv6_addr = v6.parse().ok();
        }
        if let Some(mud_url) = self.mud_url {
            device.mud_url = Some(mud_url);
        }
        if let Some(hostname) = self.hostname {
            device.hostname = hostname;
        }
        if let Some(vendor_class) = self.vendor_class {
            device.vendor_class = vendor_class;
        }
        if let Some(clipart) = self.clipart {
            device.clipart = Some(clipart);
        }
        if let Some(room_id) = self.room_id {
            device.room_id = Some(room_id);
        }
        if let Some(mac_addr) = self.mac_addr {
            device.mac_addr = mac_addr.parse::<MacAddr>().ok().map(SerdeMacAddr::from);
        }
        if let Some(duid) = self.duid {
            device.duid = Some(duid);
        }
        if let Some(collect_info) = self.collect_info {
            device.collect_info = collect_info;
        }
        if let Some(q_bit) = self.q_bit {
            device.q_bit = q_bit;
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct GuessDto {
    pub mud_url: String,
    pub model_name: Option<String>,
    pub manufacturer_name: Option<String>,
}
