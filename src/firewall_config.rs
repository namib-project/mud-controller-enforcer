// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use serde::{Deserialize, Serialize};

/// This file represent the config for firewall on openwrt.
///
/// @author Namib Group 3.

/// Represents a name of a Rule.
#[derive(Eq, PartialEq, Clone, Debug, Hash, Deserialize, Serialize)]
pub struct RuleName(String);

impl RuleName {
    /// Create new `RuleName`.
    pub fn new(name: String) -> Self {
        RuleName(name)
    }
}

/// Represents a target host for a firewall rule
#[derive(Eq, PartialEq, Clone, Debug, Deserialize, Serialize)]
pub enum RuleTargetHost {
    Ip(IpAddr),
    Hostname(String),
    FirewallDevice,
}

/// Represents a src or dst target for a firewall rule
#[derive(Eq, PartialEq, Clone, Debug, Deserialize, Serialize)]
pub struct RuleTarget {
    pub host: Option<RuleTargetHost>,
    pub port: Option<String>,
}

impl RuleTarget {
    pub fn new(host: Option<RuleTargetHost>, port: Option<String>) -> RuleTarget {
        RuleTarget { host, port }
    }
}

/// Protocols that a rule should apply to.
#[derive(Eq, PartialEq, Clone, Debug, Deserialize, Serialize)]
pub enum Protocol {
    Tcp,
    Udp,
    All,
}

/// Verdict that the firewall shall perform for a given rule.
#[derive(Eq, Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum Verdict {
    Accept,
    Reject,
    Drop,
}

/// A single firewall rule entry.
#[derive(Eq, PartialEq, Clone, Debug, Deserialize, Serialize)]
pub struct FirewallRule {
    pub rule_name: RuleName,
    pub src: RuleTarget,
    pub dst: RuleTarget,
    pub protocol: Protocol,
    pub verdict: Verdict,
}

impl FirewallRule {
    /// Create a new `FirewallRule`.
    pub fn new(
        rule_name: RuleName,
        src: RuleTarget,
        dst: RuleTarget,
        protocol: Protocol,
        verdict: Verdict,
    ) -> FirewallRule {
        FirewallRule {
            rule_name,
            src,
            dst,
            protocol,
            verdict,
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

/// Represents a device that is regulated by the firewall.
#[derive(Eq, PartialEq, Clone, Debug, Deserialize, Serialize)]
pub struct FirewallDevice {
    pub id: i64,
    pub ipv4_addr: Option<Ipv4Addr>,
    pub ipv6_addr: Option<Ipv6Addr>,
    pub rules: Vec<FirewallRule>,
    pub collect_data: bool,
}
