#[derive(Clone)]
#[allow(dead_code)]
pub enum EnFirewallType {
    Default,
    Rule,
    Zone,
}

#[derive(Clone)]
#[allow(dead_code)]
pub enum EnRuleName {
    Name(String),
}

#[derive(Clone)]
#[allow(dead_code)]
pub enum EnNetwork {
    Lan,
    Wan,
    VPN,
}

#[derive(Clone)]
#[allow(dead_code)]
pub enum EnRoute {
    Src(EnNetwork),
    Des(EnNetwork),

}

#[derive(Clone)]
#[allow(dead_code)]
pub enum EnProtocol {
    TCP,
    UDP,
    ICMP,
    ESP,
    IGMP,
    ALL,
}

#[derive(Clone)]
#[allow(dead_code)]
pub enum EnTarget {
    ACCEPT,
    REJECT,
    DROP,
}

#[derive(Clone)]
#[allow(dead_code)]
pub enum EnOptionalSettings {
    None,
    Settings(Vec<String>),
}

#[allow(dead_code)]
impl EnFirewallType {
    pub fn to_string(&self) -> String {
        match self {
            Self::Default => "defaults".to_string(),
            Self::Rule => "rule".to_string(),
            Self::Zone => "zone".to_string(),
        }
    }
    pub fn to_usize(&self) -> usize {
        match self {
            Self::Default => 0,
            Self::Rule => 1,
            Self::Zone => 2,
        }
    }
}

#[allow(dead_code)]
impl EnRuleName {
    pub fn to_string(&self) -> String {
        let mut r:String = "name='".to_string();
        match self {
            Self::Name(c) => {
                r.push_str(c);
                r.push_str("'");
                r
            },
        }

    }
}

#[allow(dead_code)]
impl EnNetwork {
    pub fn to_string(&self) -> String {
        match self {
            Self::Lan => "'lan'".to_string(),
            Self::Wan => "'wan'".to_string(),
            Self::VPN => "'vpn'".to_string(),
        }
    }
}

#[allow(dead_code)]
impl EnRoute {
    pub fn to_string(&self) -> String {
        match self {
            Self::Src(n) => "src=".to_string() + n.to_string().as_str(),
            Self::Des(n) => "dest=".to_string() + n.to_string().as_str(),
        }
    }
    pub fn get_network(&self) -> &EnNetwork {
        match self {
            Self::Src(n) => n,
            Self::Des(n) => n,
        }
    }
}

#[allow(dead_code)]
impl EnProtocol {
    pub fn to_string(&self) -> String {
        match self {
            Self::TCP => "proto='tcp'".to_string(),
            Self::UDP => "proto='udp'".to_string(),
            Self::ESP => "proto='esp'".to_string(),
            Self::ICMP => "proto='icmp'".to_string(),
            Self::IGMP => "proto='igmp'".to_string(),
            Self::ALL => "proto='all'".to_string(),
        }
    }
}

#[allow(dead_code)]
impl EnTarget {
    pub fn to_string(&self) -> String {
        match self {
            Self::ACCEPT => "target='ACCEPT'".to_string(),
            Self::REJECT => "target='REJECT'".to_string(),
            Self::DROP => "target='DROP'".to_string(),
        }
    }
}

#[allow(dead_code)]
impl EnOptionalSettings {
    pub fn unwrap(&self) -> Option<&Vec<String>> {
        match self {
            Self::None => None,
            Self::Settings(v) => Some(v),
        }
    }
}

#[derive(Clone)]
pub struct ConfigFirewall {
    firewall_type: EnFirewallType,
    rule_name: EnRuleName,
    route_network_src: EnRoute,
    route_network_dest: EnRoute,
    protocol: EnProtocol,
    target: EnTarget,
    optional_settings: EnOptionalSettings,
}

#[allow(dead_code)]
impl ConfigFirewall {
    pub fn new(firewall_type: EnFirewallType,
               rule_name: EnRuleName,
               route_network_src: EnRoute,
               route_network_dest: EnRoute,
               protocol: EnProtocol,
               target: EnTarget,
               optional_settings: EnOptionalSettings, ) -> ConfigFirewall {
        ConfigFirewall {
            firewall_type,
            rule_name,
            route_network_src,
            route_network_dest,
            protocol,
            target,
            optional_settings,
        }
    }
    pub fn to_vector_string(&self) -> Vec<String> {
        let mut query:Vec<String> = Vec::new();
        query.push(self.get_firewall_type().to_string());
        query.push(self.get_rule_name().to_string());
        query.push(self.get_route_network_src().to_string());
        query.push(self.get_route_network_dest().to_string());
        query.push(self.get_protocol().to_string());
        query.push(self.get_target().to_string());

        if self.optional_settings.unwrap() != Option::None{
            let vec = self.optional_settings.unwrap().unwrap();
            for s in vec.iter() {
                query.push(s.to_string());
            }
        }
        query
    }

    pub fn get_firewall_type(&self) -> &EnFirewallType {
        &self.firewall_type
    }
    pub fn get_rule_name(&self) -> &EnRuleName {
        &self.rule_name
    }
    pub fn get_route_network_src(&self) -> &EnRoute {
        &self.route_network_src
    }
    pub fn get_route_network_dest(&self) -> &EnRoute {
        &self.route_network_dest
    }
    pub fn get_protocol(&self) -> &EnProtocol {
        &self.protocol
    }
    pub fn get_target(&self) -> &EnTarget {
        &self.target
    }
    pub fn get_optional_settings(&self) -> &EnOptionalSettings {
        &self.optional_settings
    }

}

