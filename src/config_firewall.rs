use std::{
    collections::hash_map::DefaultHasher,
    fmt,
    hash::{Hash, Hasher},
};

use serde::{export::Formatter, Deserialize, Serialize};

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
/// Struct for src and dest configs
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NetworkConfig {
    typ: EnNetwork,
    ip: Option<String>,
    port: Option<String>,
}

impl NetworkConfig {
    pub fn new(typ: EnNetwork, ip: Option<String>, port: Option<String>) -> NetworkConfig {
        NetworkConfig { typ, ip, port }
    }
}

/// Struct for protocol
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Protocol(u32);

impl Protocol {
    /// Returns the tcp value used from uci.
    pub fn tcp() -> Self {
        Protocol(6)
    }

    pub fn udp() -> Self {
        Protocol(17)
    }

    pub fn from_number(nr: u32) -> Self {
        Protocol(nr)
    }

    pub fn all() -> Self {
        Protocol(0)
    }

    /// Return the key, value pair.
    pub fn to_option(&self) -> (String, String) {
        ("proto".to_string(), self.0.to_string())
    }
}

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
    rule_name: RuleName,
    src: NetworkConfig,
    dst: NetworkConfig,
    protocol: Protocol,
    target: EnTarget,
    optional_settings: EnOptionalSettings,
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

    /// Returns this firewall rule as list of key, value pairs.
    pub fn to_option(&self) -> Vec<(String, String)> {
        let mut query: Vec<(String, String)> = Vec::new();
        query.push(self.rule_name.to_option());
        query.push(self.protocol.to_option());
        query.push(self.target.to_option());
        query.push(("src".to_string(), self.src.typ.to_string()));
        if let Some(ip) = &self.src.ip {
            query.push(("src_ip".to_string(), ip.clone()));
        }
        if let Some(port) = &self.src.port {
            query.push(("src_port".to_string(), port.clone()));
        }
        query.push(("dest".to_string(), self.dst.typ.to_string()));
        if let Some(ip) = &self.dst.ip {
            query.push(("dest_ip".to_string(), ip.clone()));
        }
        if let Some(port) = &self.dst.port {
            query.push(("dst_port".to_string(), port.clone()));
        }
        if let Some(v) = &self.optional_settings {
            v.iter().for_each(|o| query.push(o.clone()));
        }
        query
    }

    /// Returns this rule's name
    pub fn rule_name(&self) -> &RuleName {
        &self.rule_name
    }
}

/// Stores a set of firewall rules and a config version
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FirewallConfig {
    version: String,
    rules: Vec<FirewallRule>,
}

impl FirewallConfig {
    /// Construct a new firewall config with the given version and firewall rules
    pub fn new(version: String, rules: Vec<FirewallRule>) -> Self {
        FirewallConfig { version, rules }
    }

    /// Returns the version of this config
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns a reference to the firewall rules in this config
    pub fn rules(&self) -> &Vec<FirewallRule> {
        &self.rules
    }
}
