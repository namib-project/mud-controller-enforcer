// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::field_reassign_with_default)]

use std::fmt;
use std::net::IpAddr;

use chrono::{DateTime, NaiveDateTime, Utc};
use namib_shared::firewall_config::RuleTargetHost;
use paperclip::{
    actix::Apiv2Schema,
    v2::{
        models::{DataType, DefaultSchemaRaw},
        schema::Apiv2Schema,
    },
};

use crate::error::Result;

#[derive(Debug, Clone, PartialEq)]
pub struct MudDboRefresh {
    pub url: String,
    pub expiration: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConfiguredServerDbo {
    pub server: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceControllerDbo {
    pub url: String,
    pub controller_mapping: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MudDbo {
    pub url: String,
    pub data: String,
    pub created_at: NaiveDateTime,
    pub expiration: NaiveDateTime,
}

impl MudDbo {
    pub fn parse_data(&self) -> Result<MudData> {
        Ok(serde_json::from_str::<MudData>(self.data.as_str())?)
    }
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema, Clone, Eq, PartialEq)]
pub struct MudData {
    pub url: String,
    pub masa_url: Option<String>,
    pub last_update: String,
    pub systeminfo: Option<String>,
    pub mfg_name: Option<String>,
    pub model_name: Option<String>,
    pub documentation: Option<String>,
    pub expiration: DateTime<Utc>,
    pub acllist: Vec<Acl>,
    pub acl_override: Vec<Acl>,
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema, Clone, Eq, PartialEq)]
pub struct Acl {
    pub name: String,
    pub packet_direction: AclDirection,
    pub acl_type: AclType,
    pub ace: Vec<Ace>,
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema, Clone, Eq, PartialEq)]
pub struct Ace {
    pub name: String,
    pub action: AceAction,
    pub matches: AceMatches,
}

/// YANG ACL (RFC8519) matches on layer 3 protocol header information and augmented by MUD
/// (RFC8520) with DNS names.
#[derive(Debug, Serialize, Deserialize, Apiv2Schema, Clone, Eq, PartialEq)]
pub enum L3Matches {
    Ipv4(Ipv4Matches),
    Ipv6(Ipv6Matches),
}

/// The Ipv4 header flags per RFC8519.
/// RFC8519 models this as 'bits' (each definitely true or false). We take the liberty to allow for
/// a None value with a potential semantic improvement for matches definitions in mind.
#[derive(Debug, Serialize, Deserialize, Apiv2Schema, Clone, Eq, PartialEq)]
pub struct Ipv4HeaderFlags {
    // NOTE: it is intentional that we have Options here despite not using None;
    //       this is motivated by an idea to add a third value (undefined, ignore for match) to
    //       the true/false binary to make matching more powerful; currently unimplemented.
    pub reserved: Option<bool>,
    pub fragment: Option<bool>,
    pub more: Option<bool>,
}

/// The TCP header flags per RFC8519.
/// RFC8519 models this as 'bits' (each definitely true or false). We take the liberty to allow for
/// a None value with a potential semantic improvement for matches definitions in mind.
#[derive(Debug, Serialize, Deserialize, Apiv2Schema, Clone, Eq, PartialEq)]
pub struct TcpHeaderFlags {
    // NOTE: it is intentional that we have Options here despite not using None;
    //       this is motivated by an idea to add a third value (undefined, ignore for match) to
    //       the true/false binary to make matching more powerful; currently unimplemented.
    pub cwr: Option<bool>,
    pub ece: Option<bool>,
    pub urg: Option<bool>,
    pub ack: Option<bool>,
    pub psh: Option<bool>,
    pub rst: Option<bool>,
    pub syn: Option<bool>,
    pub fin: Option<bool>,
}

/// The type of the TCP header "options" field. In MUD (per RFC8519) this value is given as
/// "binary" (meaning a base64 string), which we parse into this specific type.
#[derive(Debug, Serialize, Deserialize, Apiv2Schema, Clone, Eq, PartialEq)]
pub struct TcpOptions {
    pub kind: u8,
    pub length: Option<u8>,
    pub data: Vec<u8>,
}

/// Represents the "(ipv4)" choice node (and its child "ipv4" configuration data node, with its
/// contents), as defined in RFC8519 and augmented in RFC8520.
#[derive(Debug, Serialize, Deserialize, Apiv2Schema, Clone, Eq, PartialEq)]
pub struct Ipv4Matches {
    pub dscp: Option<u8>,
    pub ecn: Option<u8>,
    pub length: Option<u16>,
    pub ttl: Option<u8>,
    pub protocol: Option<AceProtocol>,
    pub ihl: Option<u8>,
    pub flags: Option<Ipv4HeaderFlags>,
    pub offset: Option<u16>,
    pub identification: Option<u16>,
    pub networks: SourceDest<Option<String>>,
    pub dnsnames: SourceDest<Option<String>>,
}

impl<T: Clone> SourceDest<T> {
    pub fn new(src: &T, dst: &T) -> Self {
        Self {
            src: src.clone(),
            dst: dst.clone(),
        }
    }

    /// Returns the source and destination ordered as "this" and the "other" device, based on the
    /// given `AclDirection`.
    pub fn ordered_by_direction(&self, direction: AclDirection) -> ThisOther<&T> {
        match direction {
            AclDirection::FromDevice => ThisOther {
                this_device: &self.src,
                other_device: &self.dst,
            },
            AclDirection::ToDevice => ThisOther {
                this_device: &self.dst,
                other_device: &self.src,
            },
        }
    }
}

/// Represents the two ends of some directional relationship as source and destination.
/// E.g., it could represent source and destination ports, source and destination IP addresses, ...
#[derive(Debug, Serialize, Deserialize, Apiv2Schema, Clone, Eq, PartialEq)]
pub struct SourceDest<T> {
    pub src: T,
    pub dst: T,
}

/// Represents a trait on "this" and the "other" side of a relationship.
/// E.g., it could, for a given device's communication relationship, hold the ports for "this"
/// device and the "other" device.
/// This type mainly exists to improve conversion semantics when working with source and
/// destination traits in a directional relationship (i.E. by ACL direction).
pub struct ThisOther<T> {
    pub this_device: T,
    pub other_device: T,
}

/// Represents the "(ipv6)" choice node (and its child "ipv6" configuration data node, with its
/// contents), as defined in RFC8519 and augmented in RFC8520.
#[derive(Debug, Serialize, Deserialize, Apiv2Schema, Clone, Eq, PartialEq)]
pub struct Ipv6Matches {
    pub dscp: Option<u8>,
    pub ecn: Option<u8>,
    pub length: Option<u16>,
    pub ttl: Option<u8>,
    pub protocol: Option<AceProtocol>,
    pub flow_label: Option<u32>,
    pub networks: SourceDest<Option<String>>,
    pub dnsnames: SourceDest<Option<String>>,
}

/// YANG ACL (RFC8519) matches on layer 4 protocol header information and augmented by MUD
/// (RFC8520) with matching on connection directionality for TCP.
#[derive(Debug, Serialize, Deserialize, Apiv2Schema, Clone, Eq, PartialEq)]
pub enum L4Matches {
    Tcp(TcpMatches),
    Udp(UdpMatches),
    Icmp(IcmpMatches),
}

/// Represents the "(tcp)" choice node (and its child "tcp" configuration data node, with its
/// contents), as defined in RFC8519 and augmented in RFC8520.
#[derive(Debug, Serialize, Deserialize, Apiv2Schema, Clone, Eq, PartialEq)]
pub struct TcpMatches {
    pub sequence_number: Option<u32>,
    pub acknowledgement_number: Option<u32>,
    pub data_offset: Option<u8>,
    pub reserved: Option<u8>,
    pub flags: Option<TcpHeaderFlags>,
    pub window_size: Option<u16>,
    pub urgent_pointer: Option<u16>,
    pub options: Option<TcpOptions>,
    pub source_port: Option<AcePort>,
    pub destination_port: Option<AcePort>,
    pub direction_initiated: Option<AclDirection>,
}

/// Represents the "(udp)" choice node (and its child "udp" configuration data node, with its
/// contents), as defined in RFC8519 and augmented in RFC8520.
#[derive(Debug, Serialize, Deserialize, Apiv2Schema, Clone, Eq, PartialEq)]
pub struct UdpMatches {
    pub length: Option<u16>,
    pub source_port: Option<AcePort>,
    pub destination_port: Option<AcePort>,
}

// The ICMP rest of header header field is 4 bytes long.
pub const ICMP_REST_OF_HEADER_BYTES: usize = 4;

// NOTE:
//   The ICMP rest of header header field's format depends on type and code. I don't think there is
//   any upside to further typing these values.
pub type IcmpRestOfHeader = [u8; ICMP_REST_OF_HEADER_BYTES];

/// Represents the "(icmp)" choice node (and its child "icmp" configuration data node, with its
/// contents), as defined in RFC8519 and augmented in RFC8520.
#[derive(Debug, Serialize, Deserialize, Apiv2Schema, Clone, Eq, PartialEq)]
pub struct IcmpMatches {
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub rest_of_header: Option<IcmpRestOfHeader>,
}

/// Represents the "matches" configuration data node
/// (concretely: "/acl:acls/acl:acl/acl:aces/acl:ace/acl:matches"), as defined in RFC8519 and
/// augmented in RFC8520.
#[derive(Debug, Serialize, Deserialize, Apiv2Schema, Clone, Eq, PartialEq)]
pub struct AceMatches {
    pub l3: Option<L3Matches>,
    pub l4: Option<L4Matches>,
    pub matches_augmentation: Option<MudAclMatchesAugmentation>,
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema, Clone, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct MudAclMatchesAugmentation {
    pub manufacturer: Option<String>,
    pub same_manufacturer: bool,
    pub controller: Option<String>,
    pub my_controller: bool,
    pub local: bool,
    pub model: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum AcePort {
    #[serde(rename = "single")]
    Single(u32),
    #[serde(rename = "range")]
    Range(u32, u32),
}

impl Apiv2Schema for AcePort {
    const NAME: Option<&'static str> = Some("AcePort");

    fn raw_schema() -> DefaultSchemaRaw {
        let mut schema = DefaultSchemaRaw::default();
        schema.properties.insert("single".into(), u32::raw_schema().into());
        schema
            .properties
            .insert("range".into(), <[u32; 2]>::raw_schema().into());
        schema.name = Some("AcePort".into());
        schema
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(tag = "name", content = "num")]
pub enum AceProtocol {
    Tcp,
    Udp,
    Icmp,
    Protocol(u32),
}

impl fmt::Display for AceProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
            Self::Icmp => write!(f, "icmp"),
            Self::Protocol(number) => write!(f, "other({})", number),
        }
    }
}

impl From<u8> for AceProtocol {
    fn from(p: u8) -> Self {
        match p {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            n => Self::Protocol(n.into()),
        }
    }
}

impl Apiv2Schema for AceProtocol {
    const NAME: Option<&'static str> = Some("AceProtocol");

    fn raw_schema() -> DefaultSchemaRaw {
        let mut enum_schema = DefaultSchemaRaw::default();
        enum_schema.data_type = Some(DataType::String);
        enum_schema.enum_.push(serde_json::json!("TCP"));
        enum_schema.enum_.push(serde_json::json!("UDP"));
        enum_schema.enum_.push(serde_json::json!("Protocol"));

        let mut schema = DefaultSchemaRaw::default();
        schema.properties.insert("name".into(), enum_schema.into());
        schema.required.insert("name".into());
        schema.properties.insert("num".into(), u32::raw_schema().into());

        schema
    }
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema, Clone, Eq, PartialEq)]
pub enum AceAction {
    Accept,
    Deny,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, Apiv2Schema, Eq)]
pub enum AclType {
    IPV6,
    IPV4,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Apiv2Schema, Eq, PartialEq, sqlx::Type)]
#[repr(i64)]
pub enum AclDirection {
    FromDevice = 0,
    ToDevice = 1,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AdministrativeContext {
    pub dns_mappings: Vec<DefinedServer>,
    pub ntp_mappings: Vec<DefinedServer>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DefinedServer {
    Ip(IpAddr),
    Url(String),
}

impl From<&DefinedServer> for RuleTargetHost {
    fn from(s: &DefinedServer) -> Self {
        match s {
            DefinedServer::Ip(addr) => RuleTargetHost::Ip(*addr),
            DefinedServer::Url(mud_url) => RuleTargetHost::Hostname(mud_url.clone()),
        }
    }
}

impl fmt::Display for AclDirection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    #[test]
    fn expect_port_json() {
        assert_eq!(json!(AcePort::Single(17)), json!({"single": 17}));
        assert_eq!(json!(AcePort::Range(9000, 9050)), json!({"range": [9000, 9050]}))
    }

    #[test]
    fn expect_protocol_json() {
        assert_eq!(json!(AceProtocol::Tcp), json!({"name": "Tcp"}));
        assert_eq!(json!(AceProtocol::Udp), json!({"name": "Udp"}));
        assert_eq!(json!(AceProtocol::Protocol(17)), json!({"name": "Protocol", "num": 17}))
    }
}
