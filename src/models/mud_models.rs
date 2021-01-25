#![allow(clippy::field_reassign_with_default)]

use chrono::{DateTime, Local, NaiveDateTime};
use paperclip::{
    actix::Apiv2Schema,
    v2::{
        models::{DataType, DefaultSchemaRaw},
        schema::Apiv2Schema,
    },
};

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

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "name", content = "num")]
pub enum AceProtocol {
    TCP,
    UDP,
    Protocol(u32),
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

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    #[test]
    fn expect_port_json() {
        assert_eq!(json!(AcePort::Single(17)), json!({"single": 17}));
        assert_eq!(json!(AcePort::Range(9000, 9050)), json!({"range": [9000, 9050]}))
    }

    #[test]
    fn expect_protocol_json() {
        assert_eq!(json!(AceProtocol::TCP), json!({"name": "TCP"}));
        assert_eq!(json!(AceProtocol::UDP), json!({"name": "UDP"}));
        assert_eq!(json!(AceProtocol::Protocol(17)), json!({"name": "Protocol", "num": 17}))
    }
}
