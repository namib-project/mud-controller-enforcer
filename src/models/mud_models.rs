#![allow(clippy::field_reassign_with_default)]

use chrono::{DateTime, Local, NaiveDateTime};
use paperclip::actix::Apiv2Schema;

#[derive(Debug, Clone)]
pub struct MudDbo {
    pub url: String,
    pub data: String,
    pub created_at: NaiveDateTime,
    pub expiration: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct MudData {
    pub url: String,
    pub masa_url: Option<String>,
    pub last_update: String,
    pub systeminfo: Option<String>,
    pub mfg_name: Option<String>,
    pub model_name: Option<String>,
    pub documentation: Option<String>,
    pub expiration: DateTime<Local>,
    pub acllist: Vec<Acl>,
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct Acl {
    pub name: String,
    pub packet_direction: AclDirection,
    pub acl_type: AclType,
    pub ace: Vec<Ace>,
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct Ace {
    pub name: String,
    pub action: AceAction,
    pub matches: AceMatches,
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct AceMatches {
    pub protocol: Option<AceProtocol>,
    pub direction_initiated: Option<AclDirection>,
    pub address_mask: Option<String>,
    pub dnsname: Option<String>,
    pub source_port: Option<AcePort>,
    pub destination_port: Option<AcePort>,
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub enum AcePort {
    Single(u32),
    Range(u32, u32),
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub enum AceProtocol {
    TCP,
    UDP,
    Protocol(u32),
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub enum AceAction {
    Accept,
    Deny,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, Apiv2Schema)]
pub enum AclType {
    IPV6,
    IPV4,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Apiv2Schema)]
pub enum AclDirection {
    FromDevice,
    ToDevice,
}
