#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MudJson {
    #[serde(rename = "ietf-mud:mud")]
    pub mud: MudDefinition,
    #[serde(rename = "ietf-access-control-list:acls")]
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
    pub systeminfo: String,
    #[serde(rename = "mfg-name")]
    pub mfg_name: String,
    pub documentation: String,
    #[serde(rename = "model-name")]
    pub model_name: String,
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
    #[serde(rename = "ietf-mud:mud")]
    pub mud: Option<MudExtension>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Tcp {
    #[serde(rename = "source-port")]
    pub source_port: Port,
    #[serde(rename = "destination-port")]
    pub destination_port: Port,
    #[serde(rename = "ietf-mud:direction-initiated")]
    pub direction_initiated: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Udp {
    #[serde(rename = "source-port")]
    pub source_port: Port,
    #[serde(rename = "destination-port")]
    pub destination_port: Port,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Port {
    pub operator: Option<String>,
    pub port: Option<i64>,
    #[serde(rename = "lower-port")]
    pub lower_port: Option<i64>,
    #[serde(rename = "upper-port")]
    pub upper_port: Option<i64>,
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

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ipv4 {
    pub protocol: Option<i64>,
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
    pub protocol: Option<i64>,
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
