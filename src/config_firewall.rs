use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Clone, Debug, Hash)]
pub struct RuleName(String);

impl RuleName {
    pub fn new(name: String) -> Self {
        RuleName(name)
    }
    pub fn to_string(&self) -> String {
        let mut r: String = "name='".to_string();
        r.push_str(self.0.as_str());
        r.push_str("'");
        r
    }
    pub fn to_option(&self) -> (String, String) {
        ("name".to_string(), self.0.clone())
    }
}

#[derive(Clone, Debug)]
pub enum EnNetwork {
    Lan,
    Wan,
    VPN,
}

impl EnNetwork {
    pub fn to_string(&self) -> String {
        match self {
            Self::Lan => "lan".to_string(),
            Self::Wan => "wan".to_string(),
            Self::VPN => "vpn".to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Protocol(u32);

impl Protocol {
    pub fn tcp() -> Self {
        Protocol(6)
    }

    pub fn to_string(&self) -> String {
        format!("proto='{}'", self.0)
    }

    pub fn to_option(&self) -> (String, String) {
        ("proto".to_string(), self.0.to_string())
    }
}

#[derive(Clone, Debug)]
pub enum EnRoute {
    Src(EnNetwork),
    Des(EnNetwork),
}

impl EnRoute {
    pub fn to_string(&self) -> String {
        match self {
            Self::Src(n) => format!("src='{}'", n.to_string()),
            Self::Des(n) => format!("dest='{}'", n.to_string()),
        }
    }
    pub fn get_network(&self) -> &EnNetwork {
        match self {
            Self::Src(n) => n,
            Self::Des(n) => n,
        }
    }

    pub fn to_option(&self) -> (String, String) {
        match self {
            Self::Src(n) => ("src".to_string(), n.to_string()),
            Self::Des(n) => ("dest".to_string(), n.to_string()),
        }
    }
}

#[derive(Clone, Debug)]
pub enum EnTarget {
    ACCEPT,
    REJECT,
    DROP,
}

impl EnTarget {
    pub fn to_string(&self) -> String {
        match self {
            Self::ACCEPT => "target='ACCEPT'".to_string(),
            Self::REJECT => "target='REJECT'".to_string(),
            Self::DROP => "target='DROP'".to_string(),
        }
    }
    pub fn to_option(&self) -> (String, String) {
        match self {
            Self::ACCEPT => ("target".to_string(), "ACCEPT".to_string()),
            Self::REJECT => ("target".to_string(), "REJECT".to_string()),
            Self::DROP => ("target".to_string(), "DROP".to_string()),
        }
    }
}

#[derive(Clone, Debug)]
pub enum EnOptionalSettings {
    None,
    Settings(Vec<(String, String)>),
}

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

    pub fn hash(&self) -> String {
        let mut hasher = DefaultHasher::new();
        self.rule_name().0.hash(&mut hasher);
        hasher.finish().to_string()
    }

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

    pub fn to_vector_string(&self) -> Vec<String> {
        let mut query: Vec<String> = Vec::new();
        query.push("rule".to_string());
        query.push(self.rule_name.to_string());
        query.push(self.route_network_src.to_string());
        query.push(self.route_network_dest.to_string());
        query.push(self.protocol.to_string());
        query.push(self.target.to_string());

        if let EnOptionalSettings::Settings(v) = &self.optional_settings {
            for s in v.iter() {
                query.push(format!("{}='{}'", s.0, s.1));
            }
        }
        query
    }

    pub fn rule_name(&self) -> &RuleName {
        &self.rule_name
    }
}
