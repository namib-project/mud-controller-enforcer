use serde::{Deserialize, Serialize};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

/// This file represent the config for firewall on openwrt.
///
/// Created on 11.11.2020.
///
/// @author Namib Group 3.

/// Represent the name of the Config.
#[derive(Clone, Debug, Hash, Deserialize, Serialize)]
pub struct RuleName(String);

impl RuleName {
    /// Create new Rulename.
    pub fn new(name: String) -> Self {
        RuleName(name)
    }

    /// Return the string of the of the name.
    /// Example: "name='YOURNAME'
    pub fn to_string(&self) -> String {
        let mut r: String = "name='".to_string();
        r.push_str(self.0.as_str());
        r.push_str("'");
        r
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

impl EnNetwork {
    /// Return the string of the enum.
    pub fn to_string(&self) -> String {
        match self {
            Self::LAN => "lan".to_string(),
            Self::WAN => "wan".to_string(),
            Self::VPN => "vpn".to_string(),
        }
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

    /// Return the string of the protocol.
    pub fn to_string(&self) -> String {
        format!("proto='{}'", self.0)
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
    /// Return the string of the target.
    pub fn to_string(&self) -> String {
        match self {
            Self::ACCEPT => "target='ACCEPT'".to_string(),
            Self::REJECT => "target='REJECT'".to_string(),
            Self::DROP => "target='DROP'".to_string(),
        }
    }

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
    route_network_src: EnNetwork,
    route_network_dest: EnNetwork,
    protocol: Protocol,
    pub target: EnTarget,
    optional_settings: EnOptionalSettings,
}

impl FirewallRule {
    /// Create a new ConfigFirewall.
    /// Takes Rulename, EnRoute with EnNetwork, Protocol and EnTarget.
    pub fn new(
        rule_name: RuleName,
        route_network_src: EnNetwork,
        route_network_dest: EnNetwork,
        protocol: Protocol,
        target: EnTarget,
        optional_settings: EnOptionalSettings,
    ) -> FirewallRule {
        FirewallRule {
            rule_name,
            route_network_src,
            route_network_dest,
            protocol,
            target,
            optional_settings,
        }
    }

    /// Takes the name of the RuleName and execute the hash.
    pub fn hash(&self) -> String {
        let mut hasher = DefaultHasher::new();
        self.rule_name().0.hash(&mut hasher);
        hasher.finish().to_string()
    }

    /// Takes a config as &self and return the config as vector in key, value pairs.
    pub fn to_option(&self) -> Vec<(String, String)> {
        let mut query: Vec<(String, String)> = Vec::new();
        query.push(self.rule_name.to_option());
        query.push(("src".to_string(), self.route_network_src.to_string()));
        query.push(("dest".to_string(), self.route_network_dest.to_string()));
        query.push(self.protocol.to_option());
        query.push(self.target.to_option());

        if let Some(v) = &self.optional_settings {
            for s in v.iter() {
                query.push(s.clone());
            }
        }
        query
    }

    /// Takes a config as &self and return the config as vector in strings.
    pub fn to_vector_string(&self) -> Vec<String> {
        let mut query: Vec<String> = Vec::new();
        query.push("rule".to_string());
        query.push(self.rule_name.to_string());
        query.push(format!("src='{}'", self.route_network_src.to_string()));
        query.push(format!("dest='{}'", self.route_network_dest.to_string()));
        query.push(self.protocol.to_string());
        query.push(self.target.to_string());

        if let Some(v) = &self.optional_settings {
            for s in v.iter() {
                query.push(format!("{}='{}'", s.0, s.1));
            }
        }
        query
    }

    /// rule_name getter.
    pub fn rule_name(&self) -> &RuleName {
        &self.rule_name
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FirewallConfig {
    version: String,
    rules: Vec<FirewallRule>,
}

impl FirewallConfig {
    pub fn new(version: String, rules: Vec<FirewallRule>) -> Self {
        FirewallConfig { version, rules }
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn rules(&self) -> &Vec<FirewallRule> {
        &self.rules
    }
}
