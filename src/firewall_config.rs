use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use serde::{Deserialize, Serialize};
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum NetworkHost {
    Ip(IpAddr),
    Hostname(String),
    FirewallDevice,
}

/// Struct for src and dest configs
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NetworkConfig {
    pub host: Option<NetworkHost>,
    pub port: Option<String>,
}

impl NetworkConfig {
    pub fn new(host: Option<NetworkHost>, port: Option<String>) -> NetworkConfig {
        NetworkConfig { host, port }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Protocol {
    Tcp,
    Udp,
    All,
}

/// Enum for the target: ACCEPT, REJECT and DROP.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum Target {
    ACCEPT,
    REJECT,
    DROP,
}

impl Target {
    /// Return the key, value pair of target.
    pub fn to_option(&self) -> (String, String) {
        match self {
            Self::ACCEPT => ("target".to_string(), "ACCEPT".to_string()),
            Self::REJECT => ("target".to_string(), "REJECT".to_string()),
            Self::DROP => ("target".to_string(), "DROP".to_string()),
        }
    }
}

/// This struct contains the main configuration which is needed for firewall rules.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FirewallRule {
    pub rule_name: RuleName,
    pub src: NetworkConfig,
    pub dst: NetworkConfig,
    pub protocol: Protocol,
    pub target: Target,
}

impl FirewallRule {
    /// Create a new `ConfigFirewall`.
    /// Takes `RuleName`, `EnRoute` with `EnNetwork`, `Protocol` and `EnTarget`.
    pub fn new(rule_name: RuleName, src: NetworkConfig, dst: NetworkConfig, protocol: Protocol, target: Target) -> FirewallRule {
        FirewallRule {
            rule_name,
            src,
            dst,
            protocol,
            target,
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
    pub collect_data: bool,
}

impl FirewallDevice {
    pub fn new(id: i64, ip: IpAddr, rules: Vec<FirewallRule>, collect_data: bool) -> FirewallDevice {
        FirewallDevice { id, ip, rules, collect_data }
    }
}

/// Stores a set of firewall rules and a config version
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EnforcerConfig {
    version: String,
    devices: Vec<FirewallDevice>,
}

impl EnforcerConfig {
    /// Construct a new firewall config with the given version and firewall rules
    pub fn new(version: String, devices: Vec<FirewallDevice>) -> Self {
        EnforcerConfig { version, devices }
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
