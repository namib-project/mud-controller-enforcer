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
pub struct L3Matches {
    pub protocol: Option<AceProtocol>,
    pub address_mask: Option<String>,
    pub dnsname: Option<String>,
    // TODO(ja_he): complete
}

impl L3Matches {
    pub fn empty() -> Self {
        L3Matches {
            protocol: None,
            address_mask: None,
            dnsname: None,
        }
    }
}

/// YANG ACL (RFC8519) matches on layer 4 protocol header information and augmented by MUD
/// (RFC8520) with matching on connection directionality for TCP.
#[derive(Debug, Serialize, Deserialize, Apiv2Schema, Clone, Eq, PartialEq)]
pub struct L4Matches {
    pub source_port: Option<AcePort>,
    pub destination_port: Option<AcePort>,
    pub direction_initiated: Option<AclDirection>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    // TODO(ja_he): complete
}

impl L4Matches {
    pub fn empty() -> Self {
        L4Matches {
            source_port: None,
            destination_port: None,
            direction_initiated: None,
            icmp_type: None,
            icmp_code: None,
        }
    }
}

/// Represents the "matches" configuration data node
/// (concretely: "/acl:acls/acl:acl/acl:aces/acl:ace/acl:matches"), as defined in RFC8519 and
/// augmented in RFC8520.
#[derive(Debug, Serialize, Deserialize, Apiv2Schema, Clone, Eq, PartialEq)]
pub struct AceMatches {
    pub l3: L3Matches,
    pub l4: L4Matches,
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
