use std::{
    collections::hash_map::DefaultHasher,
    fmt,
    hash::{Hash, Hasher},
};

use chrono::{DateTime, Utc};
use serde::{export::Formatter, Deserialize, Serialize};
use std::net::IpAddr;

/// This file represent the config for firewall on openwrt.
///
/// Created on 11.11.2020.
///
/// @author Namib Group 3.

/// Represent the name of the Config.
#[derive(Clone, Debug, Hash, Deserialize, Serialize)]
pub struct RuleName(String);

impl RuleName {
    /// Create new `RuleName`.
    pub fn new(name: String) -> Self {
        RuleName(name)
    }

    /// Return the key, value pair.
    /// Example: key = name, value YOURNAME.
    pub fn to_option(&self) -> (String, String) {
        ("name".to_string(), self.0.clone())
    }
}

/// Enum for the source or destination
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum EnNetwork {
    LAN,
    WAN,
    VPN,
}

impl fmt::Display for EnNetwork {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::LAN => f.write_str("lan"),
            Self::WAN => f.write_str("wan"),
            Self::VPN => f.write_str("vpn"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResolvedIp {
    pub ip: Option<IpAddr>,
    pub refresh_at: DateTime<Utc>,
}

impl Default for ResolvedIp {
    fn default() -> ResolvedIp {
        ResolvedIp {
            ip: None,
            refresh_at: chrono::MIN_DATETIME,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum NetworkHost {
    Ip(IpAddr),
    Hostname { dns_name: String, resolved_ip: ResolvedIp },
}

/// Struct for src and dest configs
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NetworkConfig {
    pub typ: EnNetwork,
    pub host: Option<NetworkHost>,
    pub port: Option<String>,
}

impl NetworkConfig {
    pub fn new(typ: EnNetwork, host: Option<NetworkHost>, port: Option<String>) -> NetworkConfig {
        NetworkConfig { typ, host, port }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Protocol {
    Tcp,
    Udp,
    All,
}

///// Struct for protocol
//#[derive(Clone, Debug, Deserialize, Serialize)]
//pub struct Protocol(u32);

//impl Protocol {
//    /// Returns the tcp value used from uci.
//    pub fn tcp() -> Self {
//        Protocol(6)
//    }
//
//    pub fn udp() -> Self {
//        Protocol(17)
//    }

//    pub fn from_number(nr: u32) -> Self {
//        Protocol(nr)
//    }

//    pub fn all() -> Self {
//        Protocol(0)
//    }

//    /// Return the key, value pair.
//    pub fn to_option(&self) -> (String, String) {
//        ("proto".to_string(), self.0.to_string())
//    }
//}

/// Enum for the target: ACCEPT, REJECT and DROP.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum EnTarget {
    ACCEPT,
    REJECT,
    DROP,
}

impl EnTarget {
    /// Return the key, value pair of target.
    pub fn to_option(&self) -> (String, String) {
        match self {
            Self::ACCEPT => ("target".to_string(), "ACCEPT".to_string()),
            Self::REJECT => ("target".to_string(), "REJECT".to_string()),
            Self::DROP => ("target".to_string(), "DROP".to_string()),
        }
    }
}

/// Enum for optional settings. Here can be added some specified rules in key, value format.
pub type EnOptionalSettings = Option<Vec<(String, String)>>;

/// This struct contains the main configuration which is needed for firewall rules.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FirewallRule {
    pub rule_name: RuleName,
    pub src: NetworkConfig,
    pub dst: NetworkConfig,
    pub protocol: Protocol,
    pub target: EnTarget,
    pub optional_settings: EnOptionalSettings,
}

impl FirewallRule {
    /// Create a new `ConfigFirewall`.
    /// Takes `RuleName`, `EnRoute` with `EnNetwork`, `Protocol` and `EnTarget`.
    pub fn new(rule_name: RuleName, src: NetworkConfig, dst: NetworkConfig, protocol: Protocol, target: EnTarget, optional_settings: EnOptionalSettings) -> FirewallRule {
        FirewallRule {
            rule_name,
            src,
            dst,
            protocol,
            target,
            optional_settings,
        }
    }

    /// Creates a hash of this firewall rule
    pub fn hash(&self) -> String {
        let mut hasher = DefaultHasher::new();
        self.rule_name().0.hash(&mut hasher);
        hasher.finish().to_string()
    }

    /// Returns this rule's name
    pub fn rule_name(&self) -> &RuleName {
        &self.rule_name
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FirewallDevice {
    pub id: i64,
    pub ip: IpAddr,
    pub rules: Vec<FirewallRule>,
}

/// Stores a set of firewall rules and a config version
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FirewallConfig {
    version: String,
    devices: Vec<FirewallDevice>,
}

impl FirewallConfig {
    /// Construct a new firewall config with the given version and firewall rules
    pub fn new(version: String, devices: Vec<FirewallDevice>) -> Self {
        FirewallConfig { version, devices }
    }

    /// Returns the version of this config
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns a reference to the firewall rules in this config
    pub fn devices(&self) -> &Vec<FirewallDevice> {
        &self.devices
    }

    /// Returns a reference to the firewall rules in this config
    pub fn devices_mut(&mut self) -> &mut Vec<FirewallDevice> {
        &mut self.devices
    }
}
