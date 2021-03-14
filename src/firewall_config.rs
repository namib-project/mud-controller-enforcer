use std::{
    collections::hash_map::DefaultHasher,
    fmt,
    hash::{Hash, Hasher},
};

use serde::{Deserialize, Serialize};
use std::{fmt::Formatter, net::IpAddr};

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
pub enum Network {
    Lan,
    Wan,
    Vpn,
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lan => f.write_str("lan"),
            Self::Wan => f.write_str("wan"),
            Self::Vpn => f.write_str("vpn"),
        }
    }
}
/// Struct for src and dest configs
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NetworkConfig {
    pub typ: Network,
    pub ip: Option<String>,
    pub port: Option<String>,
}

impl NetworkConfig {
    pub fn new(typ: Network, ip: Option<String>, port: Option<String>) -> NetworkConfig {
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
pub enum Target {
    Accept,
    Reject,
    Drop,
}

impl Target {
    /// Return the key, value pair of target.
    pub fn to_option(&self) -> (String, String) {
        match self {
            Self::Accept => ("target".to_string(), "ACCEPT".to_string()),
            Self::Reject => ("target".to_string(), "REJECT".to_string()),
            Self::Drop => ("target".to_string(), "DROP".to_string()),
        }
    }
}

/// Enum for optional settings. Here can be added some specified rules in key, value format.
pub type OptionalSettings = Option<Vec<(String, String)>>;

/// This struct contains the main configuration which is needed for firewall rules.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FirewallRule {
    rule_name: RuleName,
    src: NetworkConfig,
    dst: NetworkConfig,
    protocol: Protocol,
    target: Target,
    optional_settings: OptionalSettings,
}

impl FirewallRule {
    /// Create a new `ConfigFirewall`.
    /// Takes `RuleName`, `EnRoute` with `EnNetwork`, `Protocol` and `EnTarget`.
    pub fn new(rule_name: RuleName, src: NetworkConfig, dst: NetworkConfig, protocol: Protocol, target: Target, optional_settings: OptionalSettings) -> FirewallRule {
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
        let mut query: Vec<(String, String)> = vec![
            self.rule_name.to_option(),
            self.protocol.to_option(),
            self.target.to_option(),
            ("src".to_string(), self.src.typ.to_string()),
        ];
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KnownDevice {
    pub ip: IpAddr,
    pub collect_data: bool,
}

impl KnownDevice {
    pub fn new(ip: IpAddr, collect_data: bool) -> Self {
        Self { ip, collect_data }
    }
}

/// Stores a set of firewall rules and a config version
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EnforcerConfig {
    version: String,
    firewall_rules: Vec<FirewallRule>,
    known_devices: Vec<KnownDevice>,
    secure_name: String,
}

impl EnforcerConfig {
    /// Construct a new firewall config with the given version and firewall rules
    pub fn new(version: String, firewall_rules: Vec<FirewallRule>, known_devices: Vec<KnownDevice>, secure_name: String) -> Self {
        EnforcerConfig {
            version,
            firewall_rules,
            known_devices,
            secure_name,
        }
    }

    /// Returns the version of this config
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns a reference to the firewall rules in this config
    pub fn firewall_rules(&self) -> &Vec<FirewallRule> {
        &self.firewall_rules
    }

    pub fn known_devices(&self) -> &Vec<KnownDevice> {
        &self.known_devices
    }

    pub fn secure_name(&self) -> &str {
        &self.secure_name
    }
}
