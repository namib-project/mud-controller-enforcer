// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach, Jan Hensel
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

/// This file represent the config for firewall on openwrt.
///
/// @author Namib Group 3.

/// Represents a target host for a firewall rule
#[derive(Eq, PartialEq, Clone, Debug, Deserialize, Serialize)]
pub enum RuleTargetHost {
    /// An IP address.
    IpAddr(IpAddr),
    /// A hostname.
    Hostname(String),
    /// The `FirewallDevice` to which the rule in which this indicates the host belongs.
    FirewallDevice,
}

/// Represents the L4 information on which the firewall should match.
#[derive(Eq, PartialEq, Clone, Debug, Deserialize, Serialize)]
pub enum L4Matches {
    Tcp(TcpMatches),
    Udp(UdpMatches),
    Icmp(IcmpMatches),
}

impl L4Matches {
    /// Return the L4 protocol name as a string; intended for debug messages.
    pub fn to_protocol_string(&self) -> String {
        match self {
            L4Matches::Tcp(_) => "TCP",
            L4Matches::Udp(_) => "UDP",
            L4Matches::Icmp(_) => "ICMP",
        }
        .to_string()
    }

    /// Create an "empty" TCP `L4Matches` variant, i.E. one that does not actually match anything
    /// and thus purely serves to declare the L4 protocol to the enforcer.
    pub fn empty_tcp() -> Self {
        Self::Tcp(TcpMatches::default())
    }

    /// Create an "empty" UDP `L4Matches` variant, i.E. one that does not actually match anything
    /// and thus purely serves to declare the L4 protocol to the enforcer.
    pub fn empty_udp() -> Self {
        Self::Udp(UdpMatches::default())
    }

    /// Create an "empty" ICMP `L4Matches` variant, i.E. one that does not actually match anything
    /// and thus purely serves to declare the L4 protocol to the enforcer.
    pub fn empty_icmp() -> Self {
        Self::Icmp(IcmpMatches::default())
    }
}

/// Represents the _additional_ matching information in the L3 protocol header, i.E. any
/// _non-host_ information.
#[derive(Eq, PartialEq, Clone, Debug, Deserialize, Serialize)]
pub enum L3MatchesExtra {
    Ipv4(Ipv4MatchesExtra),
    Ipv6(Ipv6MatchesExtra),
}

/// Represents the _additional_ IPv4 header matching information, i.E. anything but the hosts
/// (address and dnsname).
#[derive(Eq, PartialEq, Clone, Debug, Deserialize, Serialize)]
pub struct Ipv4MatchesExtra {
    pub dscp: Option<u8>,
    pub ecn: Option<u8>,
    pub length: Option<u16>,
    pub ttl: Option<u8>,
    pub ihl: Option<u8>,
    pub flags: Option<Ipv4HeaderFlags>,
    pub offset: Option<u16>,
    pub identification: Option<u16>,
}

/// Represents the _additional_ IPv6 header matching information, i.E. anything but the hosts
/// (address and dnsname).
#[derive(Eq, PartialEq, Clone, Debug, Deserialize, Serialize)]
pub struct Ipv6MatchesExtra {
    pub dscp: Option<u8>,
    pub ecn: Option<u8>,
    pub length: Option<u16>,
    pub ttl: Option<u8>,
    pub flow_label: Option<u32>,
}

/// Represents either a single port or a port range (inclusive).
/// Representation is supposed to be generic, i.E. not specifically TCP or UDP.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum PortOrRange {
    Single(u16),
    Range(u16, u16),
}

/// The directionality of e.g. a connection or communication, either from or to a device.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum Direction {
    ToDevice,
    FromDevice,
}

/// The TCP header "Options" field.
/// This field (including padding) can be up to 40 bytes long in total.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct TcpOptions {
    pub kind: u8,
    pub length: Option<u8>,
    pub data: Vec<u8>,
}

/// The TCP header flags.
/// (See e.g. <https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure>)
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct TcpHeaderFlags {
    // NOTE: it is intentional that we have Options here despite not using None;
    //       this is motivated by an idea to add a third value (undefined, ignore for match) to
    //       the true/false binary to make matching more powerful; currently unimplemented.
    pub cwr: Option<bool>,
    pub ece: Option<bool>,
    pub urg: Option<bool>,
    pub ack: Option<bool>,
    pub psh: Option<bool>,
    pub rst: Option<bool>,
    pub syn: Option<bool>,
    pub fin: Option<bool>,
}

/// The IPv4 header "Flags" field.
/// (See "Flags" at <https://datatracker.ietf.org/doc/html/rfc791#section-3.1>)
#[derive(Default, Eq, PartialEq, Clone, Debug, Deserialize, Serialize)]
pub struct Ipv4HeaderFlags {
    // NOTE: it is intentional that we have Options here despite not using None;
    //       this is motivated by an idea to add a third value (undefined, ignore for match) to
    //       the true/false binary to make matching more powerful; currently unimplemented.
    pub reserved: Option<bool>,
    pub fragment: Option<bool>,
    pub more: Option<bool>,
}

/// Matchable information in the TCP header.
#[derive(Default, Eq, PartialEq, Clone, Debug, Deserialize, Serialize)]
pub struct TcpMatches {
    pub src_port: Option<PortOrRange>,
    pub dst_port: Option<PortOrRange>,
    pub sequence_number: Option<u32>,
    pub acknowledgement_number: Option<u32>,
    pub data_offset: Option<u8>,
    pub reserved: Option<u8>,
    pub flags: Option<TcpHeaderFlags>,
    pub window_size: Option<u16>,
    pub urgent_pointer: Option<u16>,
    pub options: Option<TcpOptions>,
    pub direction_initiated: Option<Direction>,
}

impl TcpMatches {
    /// Create a `TcpMatches`, only setting source and destination port explicitly (leaving all else
    /// `None`).
    pub fn only_ports(src_port: Option<PortOrRange>, dst_port: Option<PortOrRange>) -> Self {
        Self {
            src_port,
            dst_port,
            sequence_number: None,
            acknowledgement_number: None,
            data_offset: None,
            reserved: None,
            flags: None,
            window_size: None,
            urgent_pointer: None,
            options: None,
            direction_initiated: None,
        }
    }
}

/// Matchable information in the UDP header.
#[derive(Default, Eq, PartialEq, Clone, Debug, Deserialize, Serialize)]
pub struct UdpMatches {
    pub src_port: Option<PortOrRange>,
    pub dst_port: Option<PortOrRange>,
    pub length: Option<u16>,
}

impl UdpMatches {
    /// Create a `UdpMatches`, only setting source and destination port explicitly (leaving all else
    /// `None`).
    pub fn only_ports(src_port: Option<PortOrRange>, dst_port: Option<PortOrRange>) -> Self {
        Self {
            src_port,
            dst_port,
            length: None,
        }
    }
}

/// Matchable information in the ICMP header.
#[derive(Default, Eq, PartialEq, Clone, Debug, Deserialize, Serialize)]
pub struct IcmpMatches {
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub rest_of_header: Option<[u8; 4]>,
}

/// Verdict that the firewall shall perform for a given rule.
#[derive(Eq, Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum Verdict {
    Accept,
    Reject,
    Drop,
    Log(u32),
}

/// A constraint on the scope to which a rule applies.
#[derive(Eq, PartialEq, Clone, Debug, Deserialize, Serialize)]
pub enum ScopeConstraint {
    /// A union of networks. The constraint is "must be within (at least) one of the listed
    /// networks".
    IpNetworks(Vec<IpNetwork>),
    /// Just the local network. Whatever the enforcer device (router/switch) might make of that.
    JustLocal,
}

/// A single firewall rule entry.
///
/// Bears some resemblance to the MUD-ACE matches data, with the important difference that the
/// source and destination hosts are decoupled from the L3-matches information. This has the
/// benefit of easing access to the all-important host information and not requiring unnecessarily
/// matching over L3-protocol type to get e.g. DNS name information. This does mean that the data
/// model does not prohibit a rule with an IPv4 addressed host and IPv6 header match information
/// being given.
#[derive(Eq, PartialEq, Clone, Debug, Deserialize, Serialize)]
pub struct FirewallRule {
    pub rule_name: String,
    pub src: Option<RuleTargetHost>,
    pub dst: Option<RuleTargetHost>,
    pub network_constraint: Option<ScopeConstraint>,
    pub l3_matches: Option<L3MatchesExtra>,
    pub l4_matches: Option<L4Matches>,
    pub verdict: Verdict,
}

impl FirewallRule {
    /// Create a new `FirewallRule`.
    pub fn new(
        rule_name: String,
        src: Option<RuleTargetHost>,
        dst: Option<RuleTargetHost>,
        network_constraint: Option<ScopeConstraint>,
        l3_matches: Option<L3MatchesExtra>,
        l4_matches: Option<L4Matches>,
        verdict: Verdict,
    ) -> FirewallRule {
        FirewallRule {
            rule_name,
            src,
            dst,
            network_constraint,
            l3_matches,
            l4_matches,
            verdict,
        }
    }

    /// Creates a hash of this firewall rule
    pub fn hash(&self) -> String {
        let mut hasher = DefaultHasher::new();
        self.rule_name().hash(&mut hasher);
        hasher.finish().to_string()
    }

    /// Returns this rule's name
    pub fn rule_name(&self) -> &String {
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
