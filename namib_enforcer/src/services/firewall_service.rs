// Copyright 2020-2022, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach, Jasper Wiegratz, Hannes Masuch
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

#[cfg(feature = "nftables")]
use ipnetwork::IpNetwork;
#[cfg(feature = "nftables")]
use namib_shared::firewall_config::{
    FirewallDevice, FirewallRule, IcmpMatches, L3MatchesExtra, PortOrRange, ScopeConstraint, TcpHeaderFlags,
    TcpMatches, UdpMatches,
};
#[cfg(feature = "nftables")]
use namib_shared::{
    firewall_config::{L4Matches, RuleTargetHost, Verdict},
    EnforcerConfig,
};
#[cfg(feature = "nftables")]
use pnet_datalink::interfaces;
use tokio::{
    select,
    sync::{Notify, RwLock},
};

#[cfg(feature = "nftables")]
use nft::{batch::Batch, expr, schema, stmt, types};

use crate::{error::Result, services::dns::DnsWatcher, Enforcer};

const TABLE_NAME: &str = "namib";
const TABLE_NAME_BRIDGE: &str = "namib_local";
const BASE_CHAIN_NAME: &str = "base_chain";
const BASE_CHAIN_NAME_BRIDGE: &str = "base_chain";

/// Service which provides firewall configuration functionality by integrating into the linux system
/// firewall (nftables).
/// For more information on the way the linux firewall works, see [the nftables wiki](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page).
/// To construct nftables expressions, the [nft-rs](https://github.com/namib-project/nft-rs) library is used.
pub struct FirewallService {
    dns_watcher: Arc<DnsWatcher>,
    enforcer_state: Arc<RwLock<Enforcer>>,
    change_notify: Notify,
}

/// Helper enum for rule conversion.
#[derive(Debug, Clone, PartialEq)]
enum RuleAddrEntry {
    AnyAddr,
    AddrEntry(IpAddr),
}

impl From<IpAddr> for RuleAddrEntry {
    fn from(a: IpAddr) -> Self {
        RuleAddrEntry::AddrEntry(a)
    }
}

impl From<Ipv4Addr> for RuleAddrEntry {
    fn from(a: Ipv4Addr) -> Self {
        RuleAddrEntry::AddrEntry(a.into())
    }
}

impl From<Ipv6Addr> for RuleAddrEntry {
    fn from(a: Ipv6Addr) -> Self {
        RuleAddrEntry::AddrEntry(a.into())
    }
}

impl FirewallService {
    /// Creates a new `FirewallService` instance with the given enforcer state and dns watcher (generated from the dns service).
    pub(crate) fn new(enforcer_state: Arc<RwLock<Enforcer>>, watcher: DnsWatcher) -> FirewallService {
        FirewallService {
            enforcer_state,
            dns_watcher: Arc::new(watcher),
            change_notify: Notify::new(),
        }
    }

    /// Updates the current firewall config with a new value and notifies the firewall change watcher to update the firewall config.
    pub fn notify_firewall_change(&self) {
        self.change_notify.notify_one();
    }

    /// Watcher which watches for firewall or DNS resolution changes and updates the nftables firewall accordingly.
    pub async fn firewall_change_watcher(&self) {
        loop {
            select! {
                _ = self.change_notify.notified() => {}
                _ = self.dns_watcher.address_changed() => {}
            }
            self.apply_current_config()
                .await
                .unwrap_or_else(|e| error!("An error occurred while updating the firewall configuration: {:?}", e));
        }
    }

    /// Updates the nftables rules to reflect the current firewall config.
    pub async fn apply_current_config(&self) -> Result<()> {
        debug!("Configuration has changed, applying new rules to nftables");
        let config = &self.enforcer_state.read().await.config;
        self.dns_watcher.clear_watched_names().await;
        apply_firewall_config_inner(config, &self.dns_watcher).await
    }
}

#[derive(PartialEq)]
enum FirewallRuleScope {
    Inet,
    Bridge,
}

#[cfg(feature = "nftables")]
fn family_for_scope(scope: &FirewallRuleScope) -> types::NfFamily {
    match scope {
        FirewallRuleScope::Inet => types::NfFamily::INet,
        FirewallRuleScope::Bridge => types::NfFamily::Bridge,
    }
}

trait AddressPairInScope {
    fn address_pair_in_scope(&self, src_addr: &IpAddr, dest_addr: &IpAddr) -> bool;
    fn rule_address_pair_in_scope(&self, src_addr: &RuleAddrEntry, dest_addr: &RuleAddrEntry) -> bool;
}

#[cfg(feature = "nftables")]
/// retrieve ip addresses configured on local interfaces
fn get_local_ips() -> Vec<IpNetwork> {
    let mut ips: Vec<IpNetwork> = Vec::new();
    for interface in interfaces() {
        ips.append(&mut interface.ips.clone());
    }
    ips
}

#[cfg(feature = "nftables")]
impl AddressPairInScope for FirewallRuleScope {
    /// In `Bridge` scope returns true iff source and destination addr are both contained in a local subnet, else false.
    /// In `Inet` scope returns true if source and destination are in non-local or different subnets, else false.
    fn address_pair_in_scope(&self, src_addr: &IpAddr, dest_addr: &IpAddr) -> bool {
        for ip in get_local_ips() {
            if ip.contains(*src_addr) && ip.contains(*dest_addr) {
                return match *self {
                    FirewallRuleScope::Bridge => true,
                    FirewallRuleScope::Inet => false,
                };
            }
        }
        // No local interface with saddr and daddr found
        match *self {
            FirewallRuleScope::Bridge => false,
            FirewallRuleScope::Inet => true,
        }
    }

    fn rule_address_pair_in_scope(&self, src_addr: &RuleAddrEntry, dest_addr: &RuleAddrEntry) -> bool {
        if src_addr == &RuleAddrEntry::AnyAddr || dest_addr == &RuleAddrEntry::AnyAddr {
            return true; // address with 'any' is relevant in all scopes
        }
        match (src_addr, dest_addr) {
            (RuleAddrEntry::AddrEntry(src_addr), RuleAddrEntry::AddrEntry(dest_addr)) => {
                self.address_pair_in_scope(src_addr, dest_addr)
            },
            _ => unreachable!("Reached unreachable condition in address pair scope matching."),
        }
    }
}

/// Layer 3 protocol a rule operates on
#[derive(Clone)]
enum FirewallRuleProto {
    IPv4,
    IPv6,
}

impl From<IpAddr> for FirewallRuleProto {
    fn from(ipaddr: IpAddr) -> Self {
        match ipaddr {
            IpAddr::V4(_) => FirewallRuleProto::IPv4,
            IpAddr::V6(_) => FirewallRuleProto::IPv6,
        }
    }
}

#[cfg(feature = "nftables")]
pub(crate) async fn apply_firewall_config_inner(config: &EnforcerConfig, dns_watcher: &DnsWatcher) -> Result<()> {
    for scope in [FirewallRuleScope::Inet, FirewallRuleScope::Bridge] {
        let table_name = match scope {
            FirewallRuleScope::Bridge => TABLE_NAME_BRIDGE,
            FirewallRuleScope::Inet => TABLE_NAME,
        };
        debug!("Creating rules for table {}", table_name);
        let mut batch = Batch::new();
        batch.add_all(add_old_config_deletion_instructions(&scope));
        let mut device_batches = Vec::new();
        convert_config_to_nft_commands(&mut batch, config, &scope, dns_watcher, &mut device_batches).await?;

        debug!("Applying rules for table {}", table_name);
        device_batches.insert(0, batch);
        for batch in device_batches {
            let nftables = batch.to_nftables();
            trace!(
                "Generated ruleset: {}",
                serde_json::to_string_pretty(&nftables).unwrap()
            );
            nft::helper::apply_ruleset(&nftables, None, None)?;
        }
    }
    Ok(())
}

#[cfg(not(feature = "nftables"))]
pub async fn apply_firewall_config_inner(
    _config: &namib_shared::EnforcerConfig,
    _dns_watcher: &DnsWatcher,
) -> Result<()> {
    Ok(())
}

/// Creates nft commands which delete the current namib firewall table (for the given scope) if it exists and adds them to the given batch.
#[cfg(feature = "nftables")]
fn add_old_config_deletion_instructions(scope: &FirewallRuleScope) -> Vec<schema::NfObject> {
    // Create the table if it doesn't exist, otherwise removing the table might cause a NotFound error.
    // If the table already exists, this doesn't do anything.
    let table: schema::Table = create_table(scope);
    vec![
        schema::NfObject::CmdObject(schema::NfCmd::Add(schema::NfListObject::Table(table.clone()))),
        schema::NfObject::CmdObject(schema::NfCmd::Delete(schema::NfListObject::Table(table))),
    ]
}

/// Creates nft commands which create a Table object
#[cfg(feature = "nftables")]
fn create_table(scope: &FirewallRuleScope) -> schema::Table {
    match scope {
        FirewallRuleScope::Inet => schema::Table {
            family: types::NfFamily::INet,
            name: TABLE_NAME.to_string(),
            handle: None,
        },
        FirewallRuleScope::Bridge => schema::Table {
            family: types::NfFamily::Bridge,
            name: TABLE_NAME_BRIDGE.to_string(),
            handle: None,
        },
    }
}

#[cfg(feature = "nftables")]
struct FlagSets {
    set_pos: Vec<expr::Expression>,
    set_neg: Vec<expr::Expression>,
}

#[cfg(feature = "nftables")]
impl FlagSets {
    fn add_flag(&mut self, flag: Option<bool>, flag_name: &str) {
        match flag {
            Some(true) => self.set_pos.push(expr::Expression::String(flag_name.to_string())),
            Some(false) => self.set_neg.push(expr::Expression::String(flag_name.to_string())),
            None => {},
        }
    }

    fn flags_to_sets(flags: &TcpHeaderFlags) -> FlagSets {
        let mut fs = FlagSets {
            set_pos: Vec::new(),
            set_neg: Vec::new(),
        };
        fs.add_flag(flags.cwr, "cwr");
        fs.add_flag(flags.ece, "ece");
        fs.add_flag(flags.urg, "urg");
        fs.add_flag(flags.ack, "ack");
        fs.add_flag(flags.psh, "psh");
        fs.add_flag(flags.rst, "rst");
        fs.add_flag(flags.syn, "syn");
        fs.add_flag(flags.fin, "fin");
        fs
    }

    /// Generates nftables statements that match for TCP flags
    pub fn flags_to_statements(flags: &namib_shared::firewall_config::TcpHeaderFlags) -> Vec<stmt::Statement> {
        let fs = FlagSets::flags_to_sets(flags);
        let mut stmts: Vec<stmt::Statement> = Vec::new();
        let left = expr::Expression::Named(expr::NamedExpression::Payload(expr::Payload {
            protocol: "tcp".to_string(),
            field: "flags".to_string(),
        }));
        if !fs.set_pos.is_empty() {
            stmts.push(stmt::Statement::Match(stmt::Match {
                left: left.clone(),
                right: expr::Expression::Named(expr::NamedExpression::Set(fs.set_pos)),
                op: stmt::Operator::EQ,
            }));
        }
        if !fs.set_neg.is_empty() {
            stmts.push(stmt::Statement::Match(stmt::Match {
                left,
                right: expr::Expression::Named(expr::NamedExpression::Set(fs.set_neg)),
                op: stmt::Operator::NEQ,
            }));
        }
        stmts
    }
}

/// Indicates if `NftablesMatcher::nf_match_addresses()` should match on source or destination address.
enum AddressMatchOn {
    Src,
    Dest,
}

#[cfg(feature = "nftables")]
struct NftablesMatcher {}

#[cfg(feature = "nftables")]
impl NftablesMatcher {
    /// Adds netfilter expressions to match layer 3 payload, e.g. TCP/UDP port numbers.
    fn match_l3(matches: &Option<L3MatchesExtra>) -> Vec<stmt::Statement> {
        let mut expr: Vec<stmt::Statement> = Vec::new();
        match matches {
            Some(L3MatchesExtra::Ipv4(ipv4_matches)) => {
                const PROTO: &str = "ip";
                if let Some(dscp) = ipv4_matches.dscp {
                    expr.push(NftablesMatcher::match_payload(
                        PROTO,
                        "dscp",
                        expr::Expression::Number(dscp.into()),
                    ));
                }
                // Ipv4MatchesExtra.ecn ==> no nftables equivalent
                if let Some(length) = ipv4_matches.length {
                    expr.push(NftablesMatcher::match_payload(
                        PROTO,
                        "length",
                        expr::Expression::Number(length.into()),
                    ));
                }
                if let Some(ttl) = ipv4_matches.ttl {
                    expr.push(NftablesMatcher::match_payload(
                        PROTO,
                        "ttl",
                        expr::Expression::Number(ttl.into()),
                    ));
                }
                // Ipv4MatchesExtra.ihl ==> no nftables equivalent
                // Ipv4MatchesExtra.flags ==> no nftables equivalent
                if let Some(offset) = ipv4_matches.offset {
                    expr.push(NftablesMatcher::match_payload(
                        PROTO,
                        "frag-off",
                        expr::Expression::Number(offset.into()),
                    ));
                }
                if let Some(identification) = ipv4_matches.identification {
                    expr.push(NftablesMatcher::match_payload(
                        PROTO,
                        "id",
                        expr::Expression::Number(identification.into()),
                    ));
                }
            },
            Some(L3MatchesExtra::Ipv6(ipv6_matches)) => {
                const PROTO: &str = "ip6";
                if let Some(dscp) = ipv6_matches.dscp {
                    expr.push(NftablesMatcher::match_payload(
                        PROTO,
                        "dscp",
                        expr::Expression::Number(dscp.into()),
                    ));
                }
                // Ipv6MatchesExtra.ecn ==> no nftables equivalent
                if let Some(length) = ipv6_matches.length {
                    expr.push(NftablesMatcher::match_payload(
                        PROTO,
                        "length",
                        expr::Expression::Number(length.into()),
                    ));
                }
                if let Some(ttl) = ipv6_matches.ttl {
                    expr.push(NftablesMatcher::match_payload(
                        PROTO,
                        "ttl",
                        expr::Expression::Number(ttl.into()),
                    ));
                }
                if let Some(flow_label) = ipv6_matches.flow_label {
                    expr.push(NftablesMatcher::match_payload(
                        PROTO,
                        "flowlabel",
                        expr::Expression::Number(flow_label),
                    ));
                }
            },
            None => {},
        }
        expr
    }

    /// Generates nftables statements that match for a port (UDP/TCP).
    /// `field` is either `sport` or `dport`.
    fn match_port(proto: &str, field: &str, port: u16) -> stmt::Statement {
        NftablesMatcher::match_payload(proto, field, expr::Expression::Number(u32::from(port)))
    }

    /// Generates nftables statements that match for port ranges (UDP/TCP).
    /// `field` is either `sport` or `dport`.
    /// The port range is defined by start `port1` and end `port2`.
    fn match_portrange(proto: &str, field: &str, port1: u16, port2: u16) -> stmt::Statement {
        let range_expr = expr::Expression::Range(expr::Range {
            range: vec![
                expr::Expression::Number(u32::from(port1)),
                expr::Expression::Number(u32::from(port2)),
            ],
        });
        NftablesMatcher::match_payload(proto, field, range_expr)
    }

    /// Generates nftables statements that match for payloads (i.e., protocol `proto` field `field` is set to value `expr`).
    fn match_payload(proto: &str, field: &str, expr: expr::Expression) -> stmt::Statement {
        let payload_expr = expr::Expression::Named(expr::NamedExpression::Payload(expr::Payload {
            protocol: proto.to_string(),
            field: field.to_string(),
        }));
        stmt::Statement::Match(stmt::Match {
            left: payload_expr,
            right: expr,
            op: stmt::Operator::EQ,
        })
    }

    /// Generates nftables statements that match for TCP data.
    fn match_tcp_data(tcp_matchable_data: &TcpMatches) -> Vec<stmt::Statement> {
        let mut expr: Vec<stmt::Statement> = Vec::new();
        match tcp_matchable_data.dst_port {
            Some(PortOrRange::Single(port)) => expr.push(NftablesMatcher::match_port("tcp", "dport", port)),
            Some(PortOrRange::Range(port1, port2)) => {
                expr.push(NftablesMatcher::match_portrange("tcp", "dport", port1, port2));
            },
            None => {},
        }
        match tcp_matchable_data.src_port {
            Some(PortOrRange::Single(port)) => expr.push(NftablesMatcher::match_port("tcp", "sport", port)),
            Some(PortOrRange::Range(port1, port2)) => {
                expr.push(NftablesMatcher::match_portrange("tcp", "sport", port1, port2));
            },
            None => {},
        }
        if let Some(sequence_number) = tcp_matchable_data.sequence_number {
            expr.push(NftablesMatcher::match_payload(
                "tcp",
                "sequence",
                expr::Expression::Number(sequence_number),
            ));
        }
        if let Some(acknowledgement_number) = tcp_matchable_data.acknowledgement_number {
            expr.push(NftablesMatcher::match_payload(
                "tcp",
                "ackseq",
                expr::Expression::Number(acknowledgement_number),
            ));
        }
        if let Some(data_offset) = tcp_matchable_data.data_offset {
            expr.push(NftablesMatcher::match_payload(
                "tcp",
                "doff",
                expr::Expression::Number(data_offset.into()),
            ));
        }
        // tcp_matchable_data.reserved ==> 'Reserved for future use.' (RFC8519)
        if let Some(flags) = &tcp_matchable_data.flags {
            expr.extend(FlagSets::flags_to_statements(flags));
        }
        if let Some(window_size) = tcp_matchable_data.window_size {
            expr.push(NftablesMatcher::match_payload(
                "tcp",
                "window",
                expr::Expression::Number(window_size.into()),
            ));
        }
        if let Some(urgent_pointer) = tcp_matchable_data.urgent_pointer {
            expr.push(NftablesMatcher::match_payload(
                "tcp",
                "urgptr",
                expr::Expression::Number(urgent_pointer.into()),
            ));
        }
        // tcp_matchable_data.options ==> does not translate to nftables
        if let Some(direction_initiated) = &tcp_matchable_data.direction_initiated {
            expr.push(stmt::Statement::Match(stmt::Match {
                left: expr::Expression::Named(expr::NamedExpression::CT(expr::CT {
                    key: "direction".to_string(),
                    family: None,
                    dir: None,
                })),
                right: expr::Expression::String(
                    match direction_initiated {
                        // TODO: depends on `saddr` and `daddr`
                        namib_shared::firewall_config::Direction::ToDevice => "original",
                        namib_shared::firewall_config::Direction::FromDevice => "reply",
                    }
                    .to_string(),
                ),
                op: stmt::Operator::EQ,
            }));
        }
        expr
    }

    /// Generates nftables statements that match for UDP data.
    fn match_udp_data(udp_matchable_data: &UdpMatches) -> Vec<nft::stmt::Statement> {
        let mut expr: Vec<stmt::Statement> = Vec::new();
        match udp_matchable_data.dst_port {
            Some(PortOrRange::Single(port)) => expr.push(NftablesMatcher::match_port("udp", "dport", port)),
            Some(PortOrRange::Range(port1, port2)) => {
                expr.push(NftablesMatcher::match_portrange("udp", "dport", port1, port2));
            },
            None => {},
        }
        match udp_matchable_data.src_port {
            Some(PortOrRange::Single(port)) => expr.push(NftablesMatcher::match_port("udp", "sport", port)),
            Some(PortOrRange::Range(port1, port2)) => {
                expr.push(NftablesMatcher::match_portrange("udp", "sport", port1, port2));
            },
            None => {},
        }
        if let Some(length) = udp_matchable_data.length {
            expr.push(NftablesMatcher::match_payload(
                "udp",
                "length",
                expr::Expression::Number(length.into()),
            ));
        }
        expr
    }

    /// Generates nftables statements that match for ICMP data.
    fn match_icmp_data(icmp_spec: &IcmpMatches) -> Vec<nft::stmt::Statement> {
        let mut expr: Vec<stmt::Statement> = Vec::new();
        if let Some(icode) = icmp_spec.icmp_code {
            expr.push(NftablesMatcher::match_payload(
                "icmp",
                "code",
                expr::Expression::Number(u32::from(icode)),
            ));
        }
        if let Some(itype) = icmp_spec.icmp_type {
            expr.push(NftablesMatcher::match_payload(
                "icmp",
                "type",
                expr::Expression::Number(u32::from(itype)),
            ));
        }
        // IcmpMatches::rest_of_header ==> no nftables equivalent
        expr
    }

    /// Adds netfilter expressions to match layer 4 payload, e.g. TCP/UDP port numbers.
    fn match_l4(matches: &Option<L4Matches>) -> Vec<stmt::Statement> {
        let mut expr: Vec<stmt::Statement> = Vec::new();
        match matches {
            Some(L4Matches::Tcp(tcp_matchable_data)) => {
                expr.extend(NftablesMatcher::match_tcp_data(tcp_matchable_data));
            },
            Some(L4Matches::Udp(udp_matchable_data)) => {
                expr.extend(NftablesMatcher::match_udp_data(udp_matchable_data));
            },
            Some(L4Matches::Icmp(icmp_spec)) => {
                expr.extend(NftablesMatcher::match_icmp_data(icmp_spec));
            },
            None => {},
        }
        expr
    }

    /// Generates nftables statement to match on the given IPv4/IPv6 address as source or destination address
    #[cfg(feature = "nftables")]
    fn match_addresses(device_addr: &IpAddr, match_on: &AddressMatchOn) -> stmt::Statement {
        let protocol = match device_addr {
            IpAddr::V4(_) => "ip".to_string(),
            IpAddr::V6(_) => "ip6".to_string(),
        };
        let field = match match_on {
            AddressMatchOn::Src => "saddr".to_string(),
            AddressMatchOn::Dest => "daddr".to_string(),
        };
        stmt::Statement::Match(stmt::Match {
            left: expr::Expression::Named(expr::NamedExpression::Payload(expr::Payload { protocol, field })),
            right: expr::Expression::String(device_addr.to_string()),
            op: stmt::Operator::EQ,
        })
    }

    /// Generates nftables statement to match on the given IPv4/IPv6 networks as source or destination address.
    /// `reference_ip` is used to identify the protocol (IPv4 or IPv6).
    #[cfg(feature = "nftables")]
    fn match_networks(
        networks: &[IpNetwork],
        match_on: &AddressMatchOn,
        reference_ip: &IpAddr,
    ) -> Option<stmt::Statement> {
        let protocol = match reference_ip {
            IpAddr::V4(_) => "ip".to_string(),
            IpAddr::V6(_) => "ip6".to_string(),
        };
        let field = match match_on {
            AddressMatchOn::Src => "saddr".to_string(),
            AddressMatchOn::Dest => "daddr".to_string(),
        };

        let mut set_elem: Vec<expr::Expression> = Vec::new();
        for network in networks {
            match (network, reference_ip) {
                (IpNetwork::V4(v4network), IpAddr::V4(_)) => {
                    let elem = match v4network.size() {
                        // network size of 1 is an edge case, it is a single address
                        1 => expr::Expression::String(v4network.network().to_string()),
                        // IPv4 network match is an nftables `range` from first (network) address to last (broadcast) address
                        _ => expr::Expression::Range(expr::Range {
                            range: vec![
                                expr::Expression::String(v4network.network().to_string()),
                                expr::Expression::String(v4network.broadcast().to_string()),
                            ],
                        }),
                    };
                    set_elem.push(elem);
                },
                (IpNetwork::V6(v6network), IpAddr::V6(_)) => {
                    // IPv6 network match is an nftables 'prefix' object with address and prefix length
                    let addr = Box::new(expr::Expression::String(v6network.ip().to_string()));
                    let prefix: expr::Prefix = expr::Prefix {
                        addr,
                        len: v6network.prefix().into(),
                    };
                    set_elem.push(expr::Expression::Named(expr::NamedExpression::Prefix(prefix)));
                },
                (_, _) => continue, // skip networks that do not match protocol (IPv4/IPv6) of reference ip
            }
        }

        if set_elem.is_empty() {
            None
        } else {
            let network_set = expr::Expression::Named(expr::NamedExpression::Set(set_elem));
            Some(stmt::Statement::Match(nft::stmt::Match {
                left: expr::Expression::Named(expr::NamedExpression::Payload(expr::Payload { protocol, field })),
                right: network_set,
                op: nft::stmt::Operator::EQ,
            }))
        }
    }
}

#[cfg(feature = "nftables")]
fn add_device_jump_rule(
    scope: &FirewallRuleScope,
    device_addr: &IpAddr,
    table: &str,
    chain: &str,
    target_chain: &str,
) -> Vec<schema::Rule> {
    let mut jump_rules: Vec<schema::Rule> = Vec::new();
    for match_on in [&AddressMatchOn::Src, &AddressMatchOn::Dest] {
        let rule_expr: Vec<stmt::Statement> = vec![
            NftablesMatcher::match_addresses(device_addr, match_on),
            stmt::Statement::Jump(stmt::JumpTarget {
                target: target_chain.to_string(),
            }),
        ];
        jump_rules.push(schema::Rule::new(
            family_for_scope(scope),
            table.to_string(),
            chain.to_string(),
            rule_expr,
        ));
    }
    jump_rules
}

/// Converts the given firewall config into nft expressions and applies them to the supplied batch.
#[cfg(feature = "nftables")]
async fn convert_config_to_nft_commands(
    batch: &mut Batch,
    config: &EnforcerConfig,
    scope: &FirewallRuleScope,
    dns_watcher: &DnsWatcher,
    device_batches: &mut Vec<Batch>,
) -> Result<()> {
    let family = match scope {
        FirewallRuleScope::Inet => types::NfFamily::INet,
        FirewallRuleScope::Bridge => types::NfFamily::Bridge,
    };

    // Create new firewall table.
    let table = create_table(scope);
    batch.add(schema::NfListObject::Table(table.clone()));
    let table = table.name.clone();

    // Create base chain. This base chain is the entry point for the firewall table and will redirect all
    // packets corresponding to a configured device in the firewall config to its separate chain.
    let base_chain_spec = match scope {
        FirewallRuleScope::Inet => (family.clone(), BASE_CHAIN_NAME, types::NfHook::Forward, 0_i32), // NF_IP_PRI_FILTER
        FirewallRuleScope::Bridge => (family.clone(), BASE_CHAIN_NAME_BRIDGE, types::NfHook::Input, -200), // NF_BR_PRI_FILTER_BRIDGED
    };
    // If a device is not one of the configured devices, accept packets by default.
    let base_chain_name = base_chain_spec.1.to_string();
    let base_chain = schema::Chain {
        family: base_chain_spec.0,
        table: table.clone(),
        name: base_chain_name.clone(),
        newname: None,
        handle: None,
        _type: Some(types::NfChainType::Filter),
        hook: Some(base_chain_spec.2),
        prio: Some(base_chain_spec.3),
        dev: None,
        policy: Some(types::NfChainPolicy::Accept),
    };
    batch.add(schema::NfListObject::Chain(base_chain));

    // Iterate over all devices.
    for device in config.devices() {
        // Create chain which is responsible for deciding how packets for/from this device will be treated.
        let chain = format!("device_{}", device.id);
        batch.add(schema::NfListObject::Chain(schema::Chain::new(
            family.clone(),
            table.clone(),
            chain.clone(),
            None,
            None,
            None,
            None,
            None,
        )));

        // Create batch for this device
        let mut device_batch = Batch::new();

        // Create fallback rules for when applying the device batch fails: Reject all packets.
        let device_fallback_rule = schema::NfListObject::Rule(schema::Rule::new(
            family.clone(),
            table.clone(),
            chain.clone(),
            vec![stmt::Statement::Reject(Some(stmt::Reject::new(
                Some(stmt::RejectType::ICMPX),
                Some(types::RejectCode::AdminProhibited),
            )))],
        ));
        batch.add(device_fallback_rule);

        // Remove the device fallback rule by flushing the device chain in the the device batch.
        // nftables applies rulesets atomically, so this is safe.
        device_batch.add_cmd(schema::NfCmd::Flush(schema::FlushObject::Chain(schema::Chain::new(
            family.clone(),
            table.clone(),
            chain.clone(),
            None,
            None,
            None,
            None,
            None,
        ))));

        // Add device jump rules to base chain.
        let target_chain = format!("device_{}", device.id);
        if let Some(v4addr) = device.ipv4_addr {
            add_device_jump_rule(scope, &v4addr.into(), &table, &base_chain_name, target_chain.as_str())
                .iter()
                .for_each(|rule| batch.add(schema::NfListObject::Rule(rule.clone())));
        }
        if let Some(v6addr) = device.ipv6_addr {
            add_device_jump_rule(scope, &v6addr.into(), &table, &base_chain_name, target_chain.as_str())
                .iter()
                .for_each(|rule| batch.add(schema::NfListObject::Rule(rule.clone())));
        }

        // Add device rules to device chain.
        for rule_spec in &device.rules {
            add_rule_to_batch(&table, &chain, device, scope, rule_spec, dns_watcher)
                .await
                .iter()
                .flatten()
                .for_each(|rule| device_batch.add(schema::NfListObject::Rule(rule.clone())));
        }

        device_batches.push(device_batch);
    }

    Ok(())
}

// Depending on the type of host identifier (hostname, IP address or placeholder for device IP)
// for the packet source or destination, create a vector of ip addresses for this identifier.
#[cfg(feature = "nftables")]
async fn extract_rule_ips(
    host: &Option<RuleTargetHost>,
    dns_watcher: &DnsWatcher,
    device: &FirewallDevice,
) -> Vec<RuleAddrEntry> {
    match host {
        Some(RuleTargetHost::IpAddr(ipaddr)) => {
            vec![RuleAddrEntry::AddrEntry(*ipaddr)]
        },
        // Error handling: If host resolution fails, return an empty Vec. This will cause no rules
        // to be generated for the supplied host (which will then default to being rejected if no other rule matches).
        Some(RuleTargetHost::Hostname(dns_name)) => dns_watcher
            .resolve_and_watch(dns_name.as_str())
            .await
            .map(|v| v.iter().map(RuleAddrEntry::from).collect())
            .unwrap_or_default(),
        Some(RuleTargetHost::FirewallDevice) => device
            .ipv4_addr
            .map(RuleAddrEntry::from)
            .into_iter()
            .chain(device.ipv6_addr.into_iter().map(RuleAddrEntry::from))
            .collect(),
        _ => vec![RuleAddrEntry::AnyAddr],
    }
}

// // Adds a rule based on the given `rule_spec` to the given `device_batch` as part of the given `device_chain`
#[cfg(feature = "nftables")]
async fn add_rule_to_batch(
    table: &str,
    device_chain: &str,
    device: &FirewallDevice,
    scope: &FirewallRuleScope,
    rule_spec: &FirewallRule,
    dns_watcher: &DnsWatcher,
) -> Option<Vec<schema::Rule>> {
    use futures::join;

    // if the rule is constrained to local scope, only add it to the bridge chain.
    if rule_spec.network_constraint == Some(ScopeConstraint::JustLocal) && *scope != FirewallRuleScope::Bridge {
        return None;
    }
    // TODO(ja_he):
    //   Consider `ScopeConstraint::IpNetworks`, which lists a number of networks to which (as a
    //   union) the match should be constrained.
    //   We could check whether any IP addresses we use for rules are within one of those networks
    //   and filter this way.
    //   I would think, the appropriate implementation would be roughly:
    //
    //      IF have a target IP
    //      {
    //          only generate the rule if it falls within one of the listed networks
    //          (e.g. for a v4 address we can skip checking any v6 networks and for the v4 networks
    //           we use the type implementation contains or something)
    //      }
    //      ELSE (IF don't have a target IP (i.E. it's a rule that matches ports or sth))
    //      {
    //          FOR each network listed
    //          {
    //              generate a rule matching the network
    //          }
    //      }

    let mut rules: Vec<schema::Rule> = Vec::new();

    // Depending on the type of host identifier (hostname, IP address or placeholder for device IP)
    // for the packet source or destination, create a vector of ip addresses for this identifier.
    let (source_ips, dest_ips) = join!(
        extract_rule_ips(&rule_spec.src, dns_watcher, device),
        extract_rule_ips(&rule_spec.dst, dns_watcher, device)
    );

    // Create a rule for each source/destination ip combination.
    // Ideally, we would instead used nftabels sets, but these currently have the limitation that they
    // can only either contain IPv4 or IPv6 addresses, not both.
    // ~~Also, nftnl-rs does not support anonymous sets yet.~~ (nft-rs can do this)
    for source_ip in &source_ips {
        for dest_ip in &dest_ips {
            // Do not create rules which mix IPv4 and IPv6 addresses.
            // Also extract protocol reference ip.
            let protocol_reference_ip = match (source_ip, dest_ip) {
                (RuleAddrEntry::AddrEntry(saddr), RuleAddrEntry::AddrEntry(daddr)) => {
                    if (saddr.is_ipv4() && daddr.is_ipv6()) || (daddr.is_ipv4() && saddr.is_ipv6()) {
                        continue;
                    }
                    saddr
                },
                (RuleAddrEntry::AddrEntry(saddr), RuleAddrEntry::AnyAddr) => saddr,
                (RuleAddrEntry::AnyAddr, RuleAddrEntry::AddrEntry(daddr)) => daddr,
                (RuleAddrEntry::AnyAddr, RuleAddrEntry::AnyAddr) => {
                    error!("src==AnyAddr and dest==AnyAddr is not a valid rule, ignoring");
                    continue;
                },
            };

            // skip rule if it doesn't match the current scope
            if !scope.rule_address_pair_in_scope(source_ip, dest_ip) {
                continue;
            }

            // Create rule for current address combination.
            let mut expr: Vec<stmt::Statement> = Vec::new();

            // Create expressions to match source IP.
            match source_ip {
                RuleAddrEntry::AddrEntry(device_addr) => {
                    expr.push(NftablesMatcher::match_addresses(device_addr, &AddressMatchOn::Src));
                },
                RuleAddrEntry::AnyAddr => {},
            }
            // Create expressions to match destination IP.
            match dest_ip {
                RuleAddrEntry::AddrEntry(device_addr) => {
                    expr.push(NftablesMatcher::match_addresses(device_addr, &AddressMatchOn::Dest));
                },
                RuleAddrEntry::AnyAddr => {},
            }

            // Add network constraint matches
            if let Some(ScopeConstraint::IpNetworks(networks)) = &rule_spec.network_constraint {
                let match_on = match (&rule_spec.src, &rule_spec.dst) {
                    (Some(RuleTargetHost::FirewallDevice), _) => &AddressMatchOn::Dest,
                    (_, Some(RuleTargetHost::FirewallDevice)) => &AddressMatchOn::Src,
                    (_, _) => panic!("Rule with neither src nor dst as FirewallDevice."),
                };
                if let Some(networks_match) = NftablesMatcher::match_networks(networks, match_on, protocol_reference_ip)
                {
                    expr.push(networks_match);
                };
            }

            // Add layer 3 protocol matches
            expr.extend(NftablesMatcher::match_l3(&rule_spec.l3_matches));

            // Add layer 4 protocol matches
            expr.extend(NftablesMatcher::match_l4(&rule_spec.l4_matches));

            // Set verdict if current rule matches.
            match rule_spec.verdict {
                Verdict::Accept => expr.push(stmt::Statement::Accept(Some(stmt::Accept {}))),
                Verdict::Reject => expr.push(stmt::Statement::Reject(Some(stmt::Reject::new(
                    Some(stmt::RejectType::ICMPX),
                    Some(types::RejectCode::AdminProhibited),
                )))),
                Verdict::Drop => expr.push(stmt::Statement::Drop(Some(stmt::Drop {}))),
                Verdict::Log(group) => expr.push(stmt::Statement::Log(Some(stmt::Log {
                    prefix: None,
                    group: Some(group),
                    snaplen: None,
                    queue_threshold: None,
                    level: None,
                    flags: None,
                }))),
            }

            let current_rule = schema::Rule {
                family: family_for_scope(scope),
                table: table.to_string(),
                chain: device_chain.to_string(),
                expr,
                handle: None,
                index: None,
                comment: Some(rule_spec.rule_name.clone()),
            };
            rules.push(current_rule);
        }
    }
    Some(rules)
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};
    use serial_test::serial;
    use std::process::Command;

    use super::*;
    use crate::services::dns::DnsService;
    use namib_shared::firewall_config::TcpMatches;

    fn setup(devices: Vec<FirewallDevice>) -> (EnforcerConfig, DnsWatcher) {
        let config = EnforcerConfig::new(String::from("1"), devices, String::from("test"), None);
        let watcher = DnsService::new().unwrap().create_watcher();
        (config, watcher)
    }

    // these tests require access to nft command.
    // run with "sudo -E `which cargo` test -p namib_enforcer -- --ignored"

    #[tokio::test]
    #[ignore]
    #[serial]
    async fn check_empty_devices() {
        let devices: Vec<FirewallDevice> = Vec::new();
        let (config, watcher) = setup(devices);
        apply_firewall_config_inner(&config, &watcher)
            .await
            .expect("Could not apply config.");

        for family_info in [
            (FirewallRuleScope::Inet, super::TABLE_NAME, super::BASE_CHAIN_NAME),
            (
                FirewallRuleScope::Bridge,
                super::TABLE_NAME_BRIDGE,
                super::BASE_CHAIN_NAME_BRIDGE,
            ),
        ] {
            let family = family_info.0;
            let table_name = family_info.1;
            let chain_name = family_info.2;
            let family_nfname = match family {
                FirewallRuleScope::Inet => "inet",
                FirewallRuleScope::Bridge => "bridge",
            };

            let output = Command::new("nft")
                .args(["-j", "list", "chain", family_nfname, table_name, chain_name])
                .output()
                .expect("failed to execute process");
            let parsed: Value = serde_json::from_slice(&output.stdout).expect("failed to parse command output as JSON");
            let expected = json!({
            "chain": {
                "family": family_nfname,
                "table": table_name,
                "name": chain_name,
                "handle": 1,
                "type": "filter",
                "hook": match family {
                    FirewallRuleScope::Inet => "forward",
                    FirewallRuleScope::Bridge => "input",
                },
                "prio": match family {
                    FirewallRuleScope::Inet => 0,
                    FirewallRuleScope::Bridge => -200,
                },
                "policy": "accept"
            }
            });

            assert_eq!(parsed["nftables"][1], expected);
        }
    }

    #[tokio::test]
    #[ignore]
    #[serial]
    async fn check_device_with_tcp_rule() {
        let rules: Vec<FirewallRule> = vec![FirewallRule {
            rule_name: "rule_0".to_string(),
            src: Some(RuleTargetHost::FirewallDevice),
            dst: Some(RuleTargetHost::IpAddr(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))),
            l3_matches: None,
            l4_matches: Some(L4Matches::Tcp(TcpMatches::default())),
            verdict: Verdict::Accept,
            network_constraint: None,
        }];
        let device_id = 1234;
        let device = FirewallDevice {
            id: device_id,
            ipv4_addr: Some(Ipv4Addr::new(8, 8, 4, 4)),
            ipv6_addr: None,
            rules,
            collect_data: false,
        };
        let devices: Vec<FirewallDevice> = [device].to_vec();

        let (config, watcher) = setup(devices);
        apply_firewall_config_inner(&config, &watcher)
            .await
            .expect("Could not apply config.");

        for family_info in [
            (FirewallRuleScope::Inet, super::TABLE_NAME, super::BASE_CHAIN_NAME),
            (
                FirewallRuleScope::Bridge,
                super::TABLE_NAME_BRIDGE,
                super::BASE_CHAIN_NAME_BRIDGE,
            ),
        ] {
            let family = family_info.0;
            let table_name = family_info.1;
            let base_chain = family_info.2;
            let device_id = device_id.to_string();
            let family_nfname = match family {
                FirewallRuleScope::Inet => "inet",
                FirewallRuleScope::Bridge => "bridge",
            };

            for chain in [base_chain, &device_id] {
                let device_chain = &format!("device_{}", &chain).to_owned();
                let chain_name = match chain {
                    x if x == base_chain => base_chain,
                    _ => device_chain,
                };
                let cmd_args = ["-j", "list", "chain", family_nfname, table_name, chain_name];
                let output = Command::new("nft")
                    .args(cmd_args)
                    .output()
                    .expect("failed to execute process");
                let parsed: Value = match serde_json::from_slice(&output.stdout) {
                    Ok(p) => p,
                    Err(error) => panic!(
                        "failed to parse command output as JSON: command `nft {}`, output {}, error {}",
                        cmd_args.join(" "),
                        std::str::from_utf8(&output.stdout).expect("failed to read JSON bytes as UTF8"),
                        error
                    ),
                };
                let expected_chain = match chain {
                    x if x == base_chain => json!({
                    "chain": {
                        "family": family_nfname,
                        "table": table_name,
                        "name": chain_name,
                        "handle": 1,
                        "type": "filter",
                        "hook": match family {
                            FirewallRuleScope::Inet => "forward",
                            FirewallRuleScope::Bridge => "input",
                        },
                        "prio": match family {
                            FirewallRuleScope::Inet => 0,
                            FirewallRuleScope::Bridge => -200,
                        },
                        "policy": "accept"
                    }}),
                    x if x == device_id => {
                        json!({"chain": {"family": family_nfname, "handle": 2, "name": chain_name, "table": table_name}})
                    },
                    _ => panic!("unsupported chain"),
                };
                assert_eq!(parsed["nftables"][1], expected_chain);
            }
        }
    }
}
