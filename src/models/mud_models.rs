#![allow(clippy::field_reassign_with_default)]

use std::net::IpAddr;

use chrono::{DateTime, Local, NaiveDateTime};
use schemars::JsonSchema;

use crate::schema::mud_data;

#[derive(Queryable, Identifiable, AsChangeset, Serialize, Deserialize, Clone, JsonSchema)]
#[table_name = "mud_data"]
#[primary_key(url)]
pub struct MUD {
    pub url: String,
    pub data: String,
    pub created_at: NaiveDateTime,
    pub expiration: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct MUDData {
    pub url: String,
    pub masa_url: Option<String>,
    pub last_update: String,
    pub systeminfo: Option<String>,
    pub mfg_name: Option<String>,
    pub model_name: Option<String>,
    pub documentation: Option<String>,
    pub expiration: DateTime<Local>,
    pub acllist: Vec<ACL>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ACL {
    pub name: String,
    pub packet_direction: ACLDirection,
    pub acl_type: ACLType,
    pub ace: Vec<ACE>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ACE {
    pub name: String,
    pub action: ACEAction,
    pub matches: ACEMatches,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ACEMatches {
    pub protocol: Option<ACEProtocol>,
    pub direction_initiated: Option<ACLDirection>,
    pub address_mask: Option<IpAddr>,
    pub dnsname: Option<String>,
    pub source_port: Option<ACEPort>,
    pub destination_port: Option<ACEPort>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub enum ACEPort {
    Single(u32),
    Range(u32, u32),
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub enum ACEProtocol {
    TCP,
    UDP,
    Protocol(u32),
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub enum ACEAction {
    Accept,
    Deny,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub enum ACLType {
    IPV6,
    IPV4,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
pub enum ACLDirection {
    FromDevice,
    ToDevice,
}
