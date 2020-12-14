use crate::MacAddr;
use chrono::{DateTime, FixedOffset, NaiveDateTime};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    slice,
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

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
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

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub enum LeaseExpiryTime {
    LeaseLength(Duration),
    LeaseExpiryTime(DateTime<FixedOffset>),
}

pub type DuidContent = Vec<u8>;
pub type DuidType = [u8; 2];

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub enum DhcpLeaseVersionSpecificInformation {
    V4(DhcpV4LeaseVersionSpecificInformation),
    V6(DhcpV6LeaseVersionSpecificInformation),
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct DhcpV4LeaseVersionSpecificInformation {
    pub ip_addr: Ipv4Addr,
    //pub client_id: Vec<u8>,
    // dnsmasq supplies some more data using its environment variables, which could also be
    // added if necessary.
}

// For now the actual DUID content is treated as an opaque vector of octets, if required this could
// be changed to actually parse the information into a struct (having a separate field for e.g. the
// enterprise number in case of a DUID-EN).
// See https://tools.ietf.org/html/rfc8415#section-11 for more information on the contents of the
// different DUID types.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub enum Duid {
    Llt(DuidContent),
    En(DuidContent),
    Ll(DuidContent),
    Uuid(DuidContent),
    Other(DuidType, DuidContent),
}

impl ToString for Duid {
    fn to_string(&self) -> String {
        match self {
            Duid::Llt(c) => {
                let mut result = String::from("00:01");
                for b in c {
                    result.push_str(format!(":{}", hex::encode(slice::from_ref(b))).as_str());
                }
                result
            },
            Duid::En(c) => {
                let mut result = String::from("00:02");
                for b in c {
                    result.push_str(format!(":{}", hex::encode(slice::from_ref(b))).as_str());
                }
                result
            },
            Duid::Ll(c) => {
                let mut result = String::from("00:03");
                for b in c {
                    result.push_str(format!(":{}", hex::encode(slice::from_ref(b))).as_str());
                }
                result
            },
            Duid::Uuid(c) => {
                let mut result = String::from("00:04");
                for b in c {
                    result.push_str(format!(":{}", hex::encode(slice::from_ref(b))).as_str());
                }
                result
            },
            Duid::Other(t, c) => {
                let mut result = String::from(format!("{}:{}", hex::encode(slice::from_ref(&t[0])), hex::encode(slice::from_ref(&t[1]))));
                for b in c {
                    result.push_str(format!(":{}", hex::encode(slice::from_ref(b))).as_str());
                }
                result
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct DhcpV6LeaseVersionSpecificInformation {
    pub ip_addr: Ipv6Addr,
    // dnsmasq supplies some more data using its environment variables, which could also be
    // added if necessary.
    pub duid: Duid,
    //iaid: [u8; 4],
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
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
    pub tags: Vec<String>,
    pub hostname: Option<String>,
}

impl DhcpLeaseInformation {
    pub fn ip_addr(&self) -> IpAddr {
        match &self.version_specific_information {
            DhcpLeaseVersionSpecificInformation::V4(info) => info.ip_addr.into(),
            DhcpLeaseVersionSpecificInformation::V6(info) => info.ip_addr.into(),
        }
    }
}
