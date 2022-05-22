// Copyright 2020-2022, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach, Jan Hensel
// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MudJson {
    #[serde(rename = "ietf-mud:mud")]
    pub mud: MudDefinition,
    #[serde(
        alias = "ietf-access-control-list:acls",
        alias = "ietf-access-control-list:access-lists"
    )]
    pub acls: IetfAccessControlListAcls,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MudDefinition {
    #[serde(rename = "mud-version")]
    pub mud_version: i64,
    #[serde(rename = "mud-url")]
    pub mud_url: String,
    #[serde(rename = "last-update")]
    pub last_update: String,
    #[serde(rename = "cache-validity")]
    pub cache_validity: Option<i64>,
    #[serde(rename = "is-supported")]
    pub is_supported: bool,
    pub systeminfo: Option<String>,
    #[serde(rename = "mfg-name")]
    pub mfg_name: Option<String>,
    pub documentation: Option<String>,
    #[serde(rename = "model-name")]
    pub model_name: Option<String>,
    #[serde(rename = "from-device-policy")]
    pub from_device_policy: Policy,
    #[serde(rename = "to-device-policy")]
    pub to_device_policy: Policy,
    pub extensions: Option<Vec<String>>,
    #[serde(rename = "ietf-mud-brski-masa:masa-server")]
    pub masa_server: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    #[serde(rename = "access-lists")]
    pub access_lists: AccessLists,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessLists {
    #[serde(rename = "access-list")]
    pub access_list: Vec<AccessList>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessList {
    pub name: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IetfAccessControlListAcls {
    pub acl: Vec<Acl>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Acl {
    pub name: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub aces: Aces,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Aces {
    pub ace: Vec<Ace>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ace {
    pub name: String,
    pub matches: Matches,
    pub actions: Actions,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Matches {
    pub ipv4: Option<Ipv4>,
    pub ipv6: Option<Ipv6>,
    pub tcp: Option<Tcp>,
    pub udp: Option<Udp>,
    pub icmp: Option<Icmp>,
    #[serde(rename = "ietf-mud:mud")]
    pub mud: Option<MudExtension>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Tcp {
    #[serde(rename = "sequence-number")]
    pub sequence_number: Option<u32>,
    #[serde(rename = "acknowledgement-number")]
    pub acknowledgement_number: Option<u32>,
    #[serde(rename = "data-offset")]
    pub data_offset: Option<u8>,
    pub reserved: Option<u8>,
    pub flags: Option<Bits>,
    #[serde(rename = "window-size")]
    pub window_size: Option<u16>,
    #[serde(rename = "urgent-pointer")]
    pub urgent_pointer: Option<u16>,
    pub options: Option<Binary>,
    #[serde(rename = "source-port")]
    pub source_port: Option<Port>,
    #[serde(rename = "destination-port")]
    pub destination_port: Option<Port>,
    #[serde(rename = "ietf-mud:direction-initiated")]
    pub direction_initiated: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Udp {
    pub length: Option<u16>,
    #[serde(rename = "source-port")]
    pub source_port: Option<Port>,
    #[serde(rename = "destination-port")]
    pub destination_port: Option<Port>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Icmp {
    #[serde(rename = "type")]
    pub icmp_type: Option<u8>,
    pub code: Option<u8>,
    #[serde(rename = "rest-of-header")]
    pub rest_of_header: Option<Binary>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Port {
    pub operator: Option<String>,
    pub port: Option<u32>,
    #[serde(rename = "lower-port")]
    pub lower_port: Option<u32>,
    #[serde(rename = "upper-port")]
    pub upper_port: Option<u32>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MudExtension {
    #[serde(rename = "controller")]
    pub controller: Option<String>,
    #[serde(rename = "my-controller")]
    pub my_controller: Option<Vec<serde_json::Value>>,
    #[serde(rename = "local-networks")]
    pub local_networks: Option<serde_json::Value>,
    #[serde(rename = "same-manufacturer")]
    pub same_manufacturer: Option<serde_json::Value>,
    pub manufacturer: Option<serde_json::Value>,
    pub model: Option<serde_json::Value>,
}

pub type Dscp = u8;
pub type Ipv6FlowLabel = u32;

/// Per RFC7950 the `bits` type is represented as a string where bits are set if their name is
/// present in the string, not set if it is absent.
/// (also see: <https://datatracker.ietf.org/doc/html/rfc7950#section-9.7>)
pub type Bits = String;

/// According to RFC7950 the `binary` type's information is base64-encoded.
/// (also see: <https://datatracker.ietf.org/doc/html/rfc7950#section-9.8>)
pub type Binary = String;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ipv4 {
    pub dscp: Option<Dscp>,
    pub ecn: Option<u8>,
    pub length: Option<u16>,
    pub ttl: Option<u8>,
    pub protocol: Option<u8>,
    pub ihl: Option<u8>,
    pub flags: Option<Bits>,
    pub offset: Option<u16>,
    pub identification: Option<u16>,
    #[serde(rename = "source-ipv4-network")]
    pub source_ipv4_network: Option<String>,
    #[serde(rename = "destination-ipv4-network")]
    pub destination_ipv4_network: Option<String>,
    #[serde(rename = "ietf-acldns:src-dnsname")]
    pub src_dnsname: Option<String>,
    #[serde(rename = "ietf-acldns:dst-dnsname")]
    pub dst_dnsname: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ipv6 {
    pub dscp: Option<Dscp>,
    pub ecn: Option<u8>,
    pub length: Option<u16>,
    pub ttl: Option<u8>,
    pub protocol: Option<u32>,
    pub flow_label: Option<Ipv6FlowLabel>,
    #[serde(rename = "source-ipv6-network")]
    pub source_ipv6_network: Option<String>,
    #[serde(rename = "destination-ipv6-network")]
    pub destination_ipv6_network: Option<String>,
    #[serde(rename = "ietf-acldns:dst-dnsname")]
    pub dst_dnsname: Option<String>,
    #[serde(rename = "ietf-acldns:src-dnsname")]
    pub src_dnsname: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Actions {
    pub forwarding: String,
}
