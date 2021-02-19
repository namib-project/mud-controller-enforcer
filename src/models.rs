use crate::MacAddr;
use chrono::{DateTime, FixedOffset, NaiveDateTime};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct DHCPRequestData {
    pub ip_addr: IpAddr,
    pub mac_addr: MacAddr,
    pub mud_url: Option<String>,
    pub hostname: String,
    pub vendor_class: String,
    pub request_timestamp: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum DhcpEvent {
    LeaseAdded {
        event_timestamp: DateTime<FixedOffset>,
        lease_info: DhcpLeaseInformation,
    },
    LeaseDestroyed {
        event_timestamp: DateTime<FixedOffset>,
        lease_info: DhcpLeaseInformation,
    },
    ExistingLeaseUpdate {
        event_timestamp: DateTime<FixedOffset>,
        lease_info: DhcpLeaseInformation,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum LeaseExpiryTime {
    LeaseLength(Duration),
    LeaseExpiryTime(DateTime<FixedOffset>),
}

pub type DuidContent = Vec<u8>;

#[derive(Debug, Serialize, Deserialize)]
pub enum DhcpLeaseVersionSpecificInformation {
    V4(DhcpV4LeaseVersionSpecificInformation),
    V6(DhcpV6LeaseVersionSpecificInformation),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DhcpV4LeaseVersionSpecificInformation {
    pub ip_addr: Ipv4Addr,
    //pub client_id: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Duid {
    Llt(DuidContent),
    En(DuidContent),
    Ll(DuidContent),
    Uuid(DuidContent),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DhcpV6LeaseVersionSpecificInformation {
    pub ip_addr: Ipv6Addr,
    //duid: Duid,
    //iaid: [u8; 4],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DhcpLeaseInformation {
    pub version_specific_information: DhcpLeaseVersionSpecificInformation,
    pub domain: Option<String>,
    pub client_provided_hostname: Option<String>,
    pub old_hostname: Option<String>,
    pub user_classes: Vec<String>,
    pub lease_expiry: LeaseExpiryTime,
    pub time_remaining: Duration,
    pub receiver_interface: Option<String>,
    pub mac_address: Option<MacAddr>,
    pub mud_url: Option<String>,
}

impl DhcpLeaseInformation {
    pub fn ip_addr(&self) -> IpAddr {
        match &self.version_specific_information {
            DhcpLeaseVersionSpecificInformation::V4(info) => info.ip_addr.into(),
            DhcpLeaseVersionSpecificInformation::V6(info) => info.ip_addr.into(),
        }
    }
}
