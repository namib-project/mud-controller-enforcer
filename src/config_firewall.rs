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
#[derive(Clone, Debug, Hash)]
pub struct RuleName(String);

impl RuleName {
    /// Create new Rulename.
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
#[derive(Clone, Debug)]
pub enum EnNetwork {
    Lan,
    Wan,
    VPN,
}

impl EnNetwork {
    /// Return the string of the enum.
    pub fn to_string(&self) -> String {
        match self {
            Self::Lan => "lan".to_string(),
            Self::Wan => "wan".to_string(),
            Self::VPN => "vpn".to_string(),
        }
    }
}

/// Struct for protocol
#[derive(Clone, Debug)]
pub struct Protocol(u32);

impl Protocol {
    /// Returns the tcp value used from uci.
    pub fn tcp() -> Self {
        Protocol(6)
    }

    /// Return the key, value pair.
    pub fn to_option(&self) -> (String, String) {
        ("proto".to_string(), self.0.to_string())
    }
}

/// Enum for source oder destination of the firewall.
#[derive(Clone, Debug)]
pub enum EnRoute {
    Src(EnNetwork),
    Des(EnNetwork),
}

impl EnRoute {
    /// Returns the string of source or destination with protocol.
    pub fn get_network(&self) -> &EnNetwork {
        match self {
            Self::Src(n) => n,
            Self::Des(n) => n,
        }
    }

    /// Returns the key, value pair with the key, value of the network.
    pub fn to_option(&self) -> (String, String) {
        match self {
            Self::Src(n) => ("src".to_string(), n.to_string()),
            Self::Des(n) => ("dest".to_string(), n.to_string()),
        }
    }
}

/// Enum for the target: ACCEPT, REJECT and DROP.
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
pub enum EnOptionalSettings {
    None,
    Settings(Vec<(String, String)>),
}

/// This struct contains the main configuration which is needed for firewall rules.
#[derive(Clone, Debug)]
pub struct ConfigFirewall {
    rule_name: RuleName,
    route_network_src: EnRoute,
    route_network_dest: EnRoute,
    protocol: Protocol,
    target: EnTarget,
    optional_settings: EnOptionalSettings,
}

impl ConfigFirewall {
    /// Create a new ConfigFirewall.
    /// Takes Rulename, EnRoute with EnNetwork, Protocol and EnTarget.
    pub fn new(
        rule_name: RuleName,
        route_network_src: EnRoute,
        route_network_dest: EnRoute,
        protocol: Protocol,
        target: EnTarget,
        optional_settings: EnOptionalSettings,
    ) -> ConfigFirewall {
        ConfigFirewall {
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
        query.push(self.route_network_src.to_option());
        query.push(self.route_network_dest.to_option());
        query.push(self.protocol.to_option());
        query.push(self.target.to_option());

        if let EnOptionalSettings::Settings(v) = &self.optional_settings {
            for s in v.iter() {
                query.push(s.clone());
            }
        }
        query
    }

    /// rule_name getter.
    pub fn rule_name(&self) -> &RuleName {
        &self.rule_name
    }
}
