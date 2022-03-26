// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Deref,
};

use chrono::{NaiveDateTime, Utc};
use namib_shared::{
    macaddr::{MacAddr, SerdeMacAddr},
    models::{DhcpLeaseInformation, DhcpLeaseVersionSpecificInformation},
};
use paperclip::actix::Apiv2Schema;

use crate::{
    db::DbConnection,
    error::Result,
    models::{mud_models::MudData, Room},
    services::{device_config_service, mud_service, room_service},
};

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
    pub room_id: Option<i64>,
    pub clipart: Option<String>,
    pub q_bit: bool,
}

#[derive(Debug, Clone)]
pub struct Device {
    pub id: i64,
    pub name: Option<String>,
    pub ipv4_addr: Option<Ipv4Addr>,
    pub ipv6_addr: Option<Ipv6Addr>,
    pub mac_addr: Option<SerdeMacAddr>,
    pub duid: Option<String>,
    pub hostname: String,
    pub vendor_class: String,
    pub mud_url: Option<String>,
    pub collect_info: bool,
    pub last_interaction: NaiveDateTime,
    pub room_id: Option<i64>,
    pub clipart: Option<String>,
    pub q_bit: bool,
}

#[derive(Debug, Clone)]
pub struct DeviceWithRefs {
    pub inner: Device,
    pub room: Option<Room>,
    pub mud_data: Option<MudData>,
    pub controller_mappings: Vec<ConfiguredControllerMapping>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConfiguredControllerMapping {
    Ip(IpAddr),
    Uri(String),
}

impl Deref for DeviceWithRefs {
    type Target = Device;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
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

    pub async fn load_refs(self, conn: &DbConnection) -> Result<DeviceWithRefs> {
        let room = match self.room_id {
            Some(room_id) => Some(room_service::find_by_id(room_id, conn).await?),
            None => None,
        };
        let mud_data = match &self.mud_url {
            Some(mud_url) => Some(mud_service::get_or_fetch_mud(mud_url, conn).await?),
            None => None,
        };
        let controller_mappings: Vec<ConfiguredControllerMapping> = match &self.mud_url {
            Some(mud_url) => device_config_service::get_configured_controllers_for_device(mud_url, conn).await?,
            None => vec![],
        };
        Ok(DeviceWithRefs {
            inner: self,
            room,
            mud_data,
            controller_mappings,
        })
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
                .map(|m| m.parse::<MacAddr>().expect("Is valid mac addr").into()),
            duid: device.duid,
            hostname: device.hostname,
            vendor_class: device.vendor_class,
            mud_url: device.mud_url,
            collect_info: device.collect_info,
            last_interaction: device.last_interaction,
            room_id: device.room_id,
            clipart: device.clipart,
            q_bit: device.q_bit,
        }
    }
}

impl Device {
    pub fn new(lease_info: DhcpLeaseInformation, collect_info: bool) -> Self {
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
            collect_info,
            last_interaction: Utc::now().naive_utc(),
            room_id: None,
            clipart: None,
            q_bit: false,
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
