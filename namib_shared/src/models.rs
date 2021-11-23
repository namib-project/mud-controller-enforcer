// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    slice,
    time::Duration,
};

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};

use crate::macaddr::SerdeMacAddr;

/// Represents a DHCP event provided by the DHCP server.
///
/// This event is generated using hooks into the DHCP server to listen for new, modified or removed
/// clients.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub enum DhcpEvent {
    /// This event is generated if a new DHCP lease has been created in the DHCP server.
    LeaseAdded {
        event_timestamp: DateTime<FixedOffset>,
        lease_info: DhcpLeaseInformation,
    },
    /// This event is generated if a DHCP lease has been deleted in the DHCP server.
    LeaseDestroyed {
        event_timestamp: DateTime<FixedOffset>,
        lease_info: DhcpLeaseInformation,
    },
    /// This event is generated if a DHCP lease has been updated in the DHCP server, e.g. because
    /// of a hostname or MAC address change of a client.
    ExistingLeaseUpdate {
        event_timestamp: DateTime<FixedOffset>,
        lease_info: DhcpLeaseInformation,
    },
}

/// Represents the time until a DHCP lease expires.
///
/// Because some DHCP servers do not have a proper system clock (especially on embedded systems),
/// dnsmasq provides two ways to represent the lease expiry time:
/// - a lease expiry time in form of a timestamp if the server has a proper RTC.
/// - a lease length in form of a duration if the server does not have a proper RTC/if dnsmasq has
///   been compiled with the `HAVE_BROKEN_RTC` option.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub enum LeaseExpiryTime {
    LeaseLength(Duration),
    LeaseExpiryTime(DateTime<FixedOffset>),
}

/// Represents the content of a DHCP DUID according to [RFC 8415](https://tools.ietf.org/html/rfc8415#section-11).
pub type DuidContent = Vec<u8>;
/// Represents the type value of a DHCP DUID according to [RFC 8415](https://tools.ietf.org/html/rfc8415#section-11).
pub type DuidType = [u8; 2];

/// Container for DHCP-version specific information about DHCP leases (values that are specific for e.g. `DHCPv4`).
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub enum DhcpLeaseVersionSpecificInformation {
    V4(DhcpV4LeaseVersionSpecificInformation),
    V6(DhcpV6LeaseVersionSpecificInformation),
}

/// Container for DHCP lease information which is exclusive to `DHCPv4`.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct DhcpV4LeaseVersionSpecificInformation {
    pub ip_addr: Ipv4Addr,
    //pub client_id: Vec<u8>,
    // dnsmasq supplies some more data using its environment variables, which could also be
    // added if necessary.
}

/// DUID provided by DHCP clients during a request.
///
/// Instances of this enumeration represent DUID values according to [RFC 8415](https://tools.ietf.org/html/rfc8415#section-11),
/// which have been provided to the DHCP server by the clients and could potentially be used to
/// identify devices or device models (especially the DUID-EN might be interesting, depending on
/// how much it is actually used).
///
/// See [RFC 8415](https://tools.ietf.org/html/rfc8415#section-11) for more information on the contents of the
/// different DUID types.
///
/// For now, the actual DUID content is treated as an opaque vector of octets. If required, this could
/// be changed to actually parse the information into a struct (having a separate field for e.g. the
/// enterprise number in case of a DUID-EN). Note though, that according to the RFC, DUIDs should not
/// be interpreted by clients and servers and must only be compared for equality.
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
        let (mut result, c) = match self {
            Duid::Llt(c) => (String::from("00:01"), c),
            Duid::En(c) => (String::from("00:02"), c),
            Duid::Ll(c) => (String::from("00:03"), c),
            Duid::Uuid(c) => (String::from("00:04"), c),
            Duid::Other(t, c) => (
                format!(
                    "{}:{}",
                    hex::encode(slice::from_ref(&t[0])),
                    hex::encode(slice::from_ref(&t[1]))
                ),
                c,
            ),
        };
        for b in c {
            result.push_str(format!(":{}", hex::encode(slice::from_ref(b))).as_str());
        }
        result
    }
}

/// Container for DHCP lease information which is exclusive to `DHCPv6`.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct DhcpV6LeaseVersionSpecificInformation {
    pub ip_addr: Ipv6Addr,
    pub duid: Duid,
    // dnsmasq supplies some more data using its environment variables, which could also be
    // added if necessary.
    //iaid: [u8; 4],
}

/// Container for information about DHCP leases.
///
/// This information is provided by DHCP servers, e.g. using a hook script.
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
    pub mac_address: Option<SerdeMacAddr>,
    pub mud_url: Option<String>,
    pub tags: Vec<String>,
    pub hostname: Option<String>,
}

impl DhcpLeaseInformation {
    /// Return the `Ipv4` or `Ipv6` address of this Dhcp Lease
    pub fn ip_addr(&self) -> IpAddr {
        match &self.version_specific_information {
            DhcpLeaseVersionSpecificInformation::V4(info) => info.ip_addr.into(),
            DhcpLeaseVersionSpecificInformation::V6(info) => info.ip_addr.into(),
        }
    }

    /// Return the `DUID` that is contained in `DHCPv6` requests
    pub fn duid(&self) -> Option<&Duid> {
        match &self.version_specific_information {
            DhcpLeaseVersionSpecificInformation::V6(info) => Some(&info.duid),
            DhcpLeaseVersionSpecificInformation::V4(_) => None,
        }
    }
}
