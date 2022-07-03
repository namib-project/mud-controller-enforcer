// Copyright 2020-2022, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach, Jasper Wiegratz, Hannes Masuch
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(feature = "nftables")]
use std::ffi::CString;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

#[cfg(feature = "nftables")]
use ipnetwork::IpNetwork;
use namib_shared::firewall_config::{FirewallDevice, FirewallRule, ScopeConstraint};
#[cfg(feature = "nftables")]
use namib_shared::{
    firewall_config::{L4Matches, RuleTargetHost, Verdict},
    EnforcerConfig,
};
#[cfg(feature = "nftables")]
use nftnl::{
    expr::{IcmpCode, RejectionType, Verdict as VerdictExpr},
    nft_expr, Batch, Chain, FinalizedBatch, ProtoFamily, Rule, Table,
};
#[cfg(feature = "nftables")]
use pnet_datalink::interfaces;
use tokio::{
    select,
    sync::{Notify, RwLock},
};

use crate::{error::Result, services::dns::DnsWatcher, Enforcer};

/// This file represent the service for firewall on openwrt.
///
/// Created on 11.11.2020.
///
/// @author Namib Group 3.

const TABLE_NAME: &str = "namib";
const TABLE_NAME_BRIDGE: &str = "namib_local";
const BASE_CHAIN_NAME: &str = "base_chain";
const BASE_CHAIN_NAME_BRIDGE: &str = "base_chain";

/// Service which provides firewall configuration functionality by integrating into the linux system
/// firewall (nftables).
/// For more information on the way the linux firewall works, see [the nftables wiki](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page).
/// To construct nftables expressions, the [nftnl-rs](https://github.com/mullvad/nftnl-rs) library is used.
/// To send commands to the netlink interface, the [mnl-rs](https://github.com/mullvad/mnl-rs) library is used.
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
        debug!("{:?}", config);
        self.dns_watcher.clear_watched_names().await;
        apply_firewall_config_inner(config, &self.dns_watcher).await
    }
}

#[derive(PartialEq)]
enum FirewallRuleScope {
    Inet,
    Bridge,
}

trait AddressPairInScope {
    fn address_pair_in_scope(&self, src_addr: &IpAddr, dest_addr: &IpAddr) -> bool;
    fn rule_address_pair_in_scope(&self, src_addr: &RuleAddrEntry, dest_addr: &RuleAddrEntry) -> bool;
}

fn get_local_ips() -> Vec<IpNetwork> {
    let mut ips: Vec<IpNetwork> = Vec::new();
    for interface in interfaces() {
        ips.append(&mut interface.ips.clone());
    }
    ips
}

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

/// Protocol code for either IP protocol or ethertype
enum EtherNfType {
    NfType(u8),
    EtherType(u16),
}

trait EtherTypeCode {
    fn ethertype_code(&self, scope: &FirewallRuleScope) -> EtherNfType;
}

#[allow(clippy::cast_possible_truncation)]
impl EtherTypeCode for FirewallRuleProto {
    fn ethertype_code(&self, scope: &FirewallRuleScope) -> EtherNfType {
        match self {
            FirewallRuleProto::IPv4 => match scope {
                FirewallRuleScope::Inet => EtherNfType::NfType(libc::NFPROTO_IPV4 as u8),
                FirewallRuleScope::Bridge => EtherNfType::EtherType((libc::ETH_P_IP as u16).to_be()),
            },
            FirewallRuleProto::IPv6 => match scope {
                FirewallRuleScope::Inet => EtherNfType::NfType(libc::NFPROTO_IPV6 as u8),
                FirewallRuleScope::Bridge => EtherNfType::EtherType((libc::ETH_P_IPV6 as u16).to_be()),
            },
        }
    }
}

trait ProtocolCode {
    /// Returns IP protocol code
    fn proto_code(&self, l3proto: &FirewallRuleProto) -> u32;
}

impl ProtocolCode for L4Matches {
    fn proto_code(&self, l3proto: &FirewallRuleProto) -> u32 {
        match self {
            L4Matches::Tcp(_) => libc::IPPROTO_TCP as u32,
            L4Matches::Udp(_) => libc::IPPROTO_UDP as u32,
            L4Matches::Icmp(_) => match l3proto {
                FirewallRuleProto::IPv4 => libc::IPPROTO_ICMP as u32,
                FirewallRuleProto::IPv6 => libc::IPPROTO_ICMPV6 as u32,
            },
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
        add_old_config_deletion_instructions(&mut batch, &scope);
        let mut device_batches = Vec::new();
        convert_config_to_nftnl_commands(&mut batch, config, &scope, dns_watcher, &mut device_batches).await?;
        let batch = batch.finalize();
        debug!("Applying rules for table {}", table_name);
        if let Err(e) = send_and_process(&batch, &device_batches) {
            error!("Error sending firewall configuration to netfilter: {:?}", e);
            return Err(e);
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

/// Creates nftnl expressions which delete the current namib firewall table (for the given scope) if it exists and adds them to the given batch.
#[cfg(feature = "nftables")]
fn add_old_config_deletion_instructions(batch: &mut Batch, scope: &FirewallRuleScope) {
    // Create the table if it doesn't exist, otherwise removing the table might cause a NotFound error.
    // If the table already exists, this doesn't do anything.
    let table = create_table(scope);
    batch.add(&table, nftnl::MsgType::Add);
    // Delete the table.
    let table = create_table(scope);
    batch.add(&table, nftnl::MsgType::Del);
}

#[cfg(feature = "nftables")]
fn create_table(scope: &FirewallRuleScope) -> Table {
    match scope {
        FirewallRuleScope::Inet => Table::new(&CString::new(TABLE_NAME).unwrap(), ProtoFamily::Inet),
        FirewallRuleScope::Bridge => Table::new(&CString::new(TABLE_NAME_BRIDGE).unwrap(), ProtoFamily::Bridge),
    }
}

/// Adds netfilter instructions to match ipv4 or ipv6 protocol in rule.
#[cfg(feature = "nftables")]
fn nf_match_l3proto(rule: &mut Rule, scope: &FirewallRuleScope, proto: &FirewallRuleProto) {
    match scope {
        FirewallRuleScope::Bridge => rule.add_expr(&nft_expr!(meta proto)), // bridge uses ethertype
        FirewallRuleScope::Inet => rule.add_expr(&nft_expr!(meta nfproto)), // inet uses ip code
    }
    match proto.ethertype_code(scope) {
        EtherNfType::EtherType(proto_code) => rule.add_expr(&nft_expr!(cmp == proto_code)),
        EtherNfType::NfType(proto_code) => rule.add_expr(&nft_expr!(cmp == proto_code)),
    };
}

/// Adds netfilter instructions to match the given layer 4 protocol in rule.
#[cfg(feature = "nftables")]
fn nf_match_l4proto(rule: &mut Rule, l3proto: &FirewallRuleProto, maybe_l4proto: &Option<L4Matches>) {
    if let Some(l4proto) = maybe_l4proto {
        match l3proto {
            FirewallRuleProto::IPv4 => rule.add_expr(&nft_expr!(payload ipv4 protocol)),
            FirewallRuleProto::IPv6 => rule.add_expr(&nft_expr!(payload ipv6 nextheader)),
        }
        rule.add_expr(&nft_expr!(cmp == l4proto.proto_code(l3proto)));
    }
}

/// Adds netfilter expressions to match layer 4 payload, e.g. TCP/UDP port numbers.
#[cfg(feature = "nftables")]
fn nf_match_l4payload(rule: &mut Rule, rule_spec: &FirewallRule, l3proto: &Option<FirewallRuleProto>) {
    use namib_shared::firewall_config::PortOrRange;

    match &rule_spec.l4_matches {
        // TODO(ja_he): do we not handle port ranges?
        Some(L4Matches::Tcp(tcp_matchable_data)) => {
            match tcp_matchable_data.dst_port {
                Some(PortOrRange::Single(port)) => {
                    rule.add_expr(&nft_expr!(payload tcp dport));
                    rule.add_expr(&nft_expr!(cmp == port.to_be()));
                },
                Some(PortOrRange::Range(_, _)) => todo!(),
                None => {},
            }
            match tcp_matchable_data.src_port {
                Some(PortOrRange::Single(port)) => {
                    rule.add_expr(&nft_expr!(payload tcp sport));
                    rule.add_expr(&nft_expr!(cmp == port.to_be()));
                },
                Some(PortOrRange::Range(_, _)) => todo!(),
                None => {},
            }
        },
        Some(L4Matches::Udp(udp_matchable_data)) => {
            match udp_matchable_data.dst_port {
                Some(PortOrRange::Single(port)) => {
                    rule.add_expr(&nft_expr!(payload tcp dport));
                    rule.add_expr(&nft_expr!(cmp == port.to_be()));
                },
                Some(PortOrRange::Range(_, _)) => todo!(),
                None => {},
            }
            match udp_matchable_data.src_port {
                Some(PortOrRange::Single(port)) => {
                    rule.add_expr(&nft_expr!(payload tcp sport));
                    rule.add_expr(&nft_expr!(cmp == port.to_be()));
                },
                Some(PortOrRange::Range(_, _)) => todo!(),
                None => {},
            }
        },
        Some(L4Matches::Icmp(icmp_spec)) => {
            /// TODO: this produces the following `nft list ruleset` output for code==123 and type==234: `@th,0,8 234 @th,8,8 123`
            use nftnl::expr::IcmpHeaderField;
            for icmp_data in [
                (IcmpHeaderField::Type, icmp_spec.icmp_type),
                (IcmpHeaderField::Code, icmp_spec.icmp_code),
            ] {
                match (l3proto, icmp_data) {
                    (Some(FirewallRuleProto::IPv4), (IcmpHeaderField::Type, Some(_))) => {
                        rule.add_expr(&nft_expr!(payload icmp icmptype));
                    },
                    (Some(FirewallRuleProto::IPv4), (IcmpHeaderField::Code, Some(_))) => {
                        rule.add_expr(&nft_expr!(payload icmp code));
                    },
                    (Some(FirewallRuleProto::IPv6), (IcmpHeaderField::Type, Some(_))) => {
                        rule.add_expr(&nft_expr!(payload icmpv6 icmptype));
                    },
                    (Some(FirewallRuleProto::IPv6), (IcmpHeaderField::Code, Some(_))) => {
                        rule.add_expr(&nft_expr!(payload icmpv6 code));
                    },
                    (None, (_, _)) => panic!("L3 protocol not specified for ICMP rule."),
                    _ => {},
                }
                if let Some(icmp_data) = icmp_data.1 {
                    rule.add_expr(&nft_expr!(cmp == icmp_data));
                }
            }
        },
        None => {},
    }
}

/// Indicates if `nf_match_addresses()` should match on source or destination address.
enum AddressMatchOn {
    Src,
    Dest,
}

/// Adds netfilter instructions to a rule to match on the given IPv4/IPv6 address as source or destination address
#[cfg(feature = "nftables")]
fn nf_match_addresses(rule: &mut Rule, device_addr: &IpAddr, match_on: &AddressMatchOn) {
    // Match rule if source or target address is configured device.
    match device_addr {
        IpAddr::V4(v4addr) => {
            match match_on {
                AddressMatchOn::Src => rule.add_expr(&nft_expr!(payload ipv4 saddr)),
                AddressMatchOn::Dest => rule.add_expr(&nft_expr!(payload ipv4 daddr)),
            }
            rule.add_expr(&nft_expr!(cmp == *v4addr));
        },
        IpAddr::V6(v6addr) => {
            match match_on {
                AddressMatchOn::Src => rule.add_expr(&nft_expr!(payload ipv6 saddr)),
                AddressMatchOn::Dest => rule.add_expr(&nft_expr!(payload ipv6 daddr)),
            }
            rule.add_expr(&nft_expr!(cmp == *v6addr));
        },
    }
}

#[cfg(feature = "nftables")]
fn add_device_jump_rule(
    batch: &mut Batch,
    base_chain: &Chain,
    scope: &FirewallRuleScope,
    device_addr: IpAddr,
    target_chain: &str,
) {
    // Create two rules in the base chain, one for packets coming from the device and one for packets going to the device.
    let mut device_jump_rule_src = Rule::new(base_chain);
    let mut device_jump_rule_dst = Rule::new(base_chain);
    // Match rule if source or target address is configured device.
    let l3proto: FirewallRuleProto = device_addr.into();
    nf_match_l3proto(&mut device_jump_rule_src, scope, &l3proto);
    nf_match_l3proto(&mut device_jump_rule_dst, scope, &l3proto);
    nf_match_addresses(&mut device_jump_rule_src, &device_addr, &AddressMatchOn::Src);
    nf_match_addresses(&mut device_jump_rule_dst, &device_addr, &AddressMatchOn::Dest);
    // If these rules apply, jump to the chain responsible for handling this device.
    device_jump_rule_src.add_expr(&nft_expr!(verdict jump CString::new(target_chain).unwrap()));
    device_jump_rule_dst.add_expr(&nft_expr!(verdict jump CString::new(target_chain).unwrap()));
    batch.add(&device_jump_rule_src, nftnl::MsgType::Add);
    batch.add(&device_jump_rule_dst, nftnl::MsgType::Add);
}

/// Converts the given firewall config into nftnl expressions and applies them to the supplied batch.
#[cfg(feature = "nftables")]
async fn convert_config_to_nftnl_commands(
    batch: &mut Batch,
    config: &EnforcerConfig,
    scope: &FirewallRuleScope,
    dns_watcher: &DnsWatcher,
    device_batches: &mut Vec<FinalizedBatch>,
) -> Result<()> {
    // Create new firewall table.
    let table = create_table(scope);
    batch.add(&table, nftnl::MsgType::Add);

    // Create base chain. This base chain is the entry point for the firewall table and will redirect all
    // packets corresponding to a configured device in the firewall config to its separate chain.
    let base_chain_name = match scope {
        FirewallRuleScope::Inet => BASE_CHAIN_NAME,
        FirewallRuleScope::Bridge => BASE_CHAIN_NAME_BRIDGE,
    };
    let mut base_chain = Chain::new(&CString::new(base_chain_name).unwrap(), &table);
    let base_chain_hook = match scope {
        FirewallRuleScope::Inet => nftnl::Hook::Forward,
        FirewallRuleScope::Bridge => nftnl::Hook::In,
    };
    let priority: i32 = match scope {
        FirewallRuleScope::Inet => 0,      // NF_IP_PRI_FILTER
        FirewallRuleScope::Bridge => -200, // NF_BR_PRI_FILTER_BRIDGED
    };
    base_chain.set_hook(base_chain_hook, priority);
    // If a device is not one of the configured devices, accept packets by default.
    base_chain.set_policy(nftnl::Policy::Accept);
    batch.add(&base_chain, nftnl::MsgType::Add);

    // Iterate over all devices.
    for device in config.devices() {
        // Create chain which is responsible for deciding how packets for/from this device will be treated.
        let device_chain = Chain::new(&CString::new(format!("device_{}", device.id)).unwrap(), &table);
        batch.add(&device_chain, nftnl::MsgType::Add);

        let mut device_batch = Batch::new();

        // Create fallback rules for when applying the device batch fails: Reject all packets.
        let mut device_fallback_rule = Rule::new(&device_chain);
        device_fallback_rule.add_expr(&VerdictExpr::Reject(RejectionType::Icmp(IcmpCode::AdminProhibited)));
        batch.add(&device_fallback_rule, nftnl::MsgType::Add);
        // If the device batch is successfully applied, delete the fallback rule.
        device_batch.add(&device_fallback_rule, nftnl::MsgType::Del);

        let target_chain = format!("device_{}", device.id);
        if let Some(v4addr) = device.ipv4_addr {
            add_device_jump_rule(batch, &base_chain, scope, v4addr.into(), target_chain.as_str());
        }
        if let Some(v6addr) = device.ipv6_addr {
            add_device_jump_rule(batch, &base_chain, scope, v6addr.into(), target_chain.as_str());
        }

        // Iterate over device rules.
        for rule_spec in &device.rules {
            add_rule_to_batch(&device_chain, &mut device_batch, device, scope, rule_spec, dns_watcher).await?;
        }

        // Add log rules for denials
        if let Some(v4addr) = device.ipv4_addr {
            add_log_rules(&device_chain, &mut device_batch, scope, v4addr.into());
        }
        if let Some(v6addr) = device.ipv6_addr {
            add_log_rules(&device_chain, &mut device_batch, scope, v6addr.into());
        }

        device_batches.push(device_batch.finalize());
    }

    Ok(())
}

/// Adds a rule to log packets to a specified log groups
#[cfg(feature = "nftables")]
fn add_log_rules(device_chain: &Chain, device_batch: &mut Batch, scope: &FirewallRuleScope, device_addr: IpAddr) {
    use namib_shared::flow_scope::LogGroup;
    if !(scope == &FirewallRuleScope::Inet || scope == &FirewallRuleScope::Bridge) {
        return;
    }
    let l3proto = match device_addr {
        IpAddr::V4(_) => FirewallRuleProto::IPv4,
        IpAddr::V6(_) => FirewallRuleProto::IPv6,
    };

    for direction in [
        (&AddressMatchOn::Src, LogGroup::DenialsFromDevice),
        (&AddressMatchOn::Dest, LogGroup::DenialsToDevice),
    ] {
        let mut rule = Rule::new(device_chain);
        nf_match_l3proto(&mut rule, scope, &l3proto);
        nf_match_addresses(&mut rule, &device_addr, direction.0);
        rule.add_expr(&nft_expr!(log group (direction.1 as u32)));
        device_batch.add(&rule, nftnl::MsgType::Add);
    }
}

// Adds a rule based on the given `rule_spec` to the given `device_batch` as part of the given `device_chain`
#[cfg(feature = "nftables")]
async fn add_rule_to_batch(
    device_chain: &Chain<'_>,
    device_batch: &mut Batch,
    device: &FirewallDevice,
    scope: &FirewallRuleScope,
    rule_spec: &FirewallRule,
    dns_watcher: &DnsWatcher,
) -> Result<()> {
    // if the rule is constrained to local scope, only add it to the bridge chain.
    if rule_spec.network_constraint == Some(ScopeConstraint::JustLocal) && *scope != FirewallRuleScope::Bridge {
        return Ok(());
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

    // Depending on the type of host identifier (hostname, IP address or placeholder for device IP)
    // for the packet source or destination, create a vector of ip addresses for this identifier.
    let source_ips: Vec<RuleAddrEntry> = match &rule_spec.src {
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
    };
    let dest_ips: Vec<RuleAddrEntry> = match &rule_spec.dst {
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
    };

    // Create a rule for each source/destination ip combination.
    // Ideally, we would instead used nftnl sets, but these currently have the limitation that they
    // can only either contain IPv4 or IPv6 addresses, not both. Also, nftnl-rs does not support anonymous
    // sets yet.
    for source_ip in &source_ips {
        for dest_ip in &dest_ips {
            let protocol_reference_ip;
            // Do not create rules which mix IPv4 and IPv6 addresses. Also, save at least one specified IP to match for protocol later on.
            if let &RuleAddrEntry::AddrEntry(saddr) = source_ip {
                if let RuleAddrEntry::AddrEntry(daddr) = dest_ip {
                    if (saddr.is_ipv4() && daddr.is_ipv6()) || (daddr.is_ipv4() && saddr.is_ipv6()) {
                        continue;
                    }
                }
                protocol_reference_ip = Some(saddr);
            } else if let &RuleAddrEntry::AddrEntry(daddr) = dest_ip {
                protocol_reference_ip = Some(daddr);
            } else {
                protocol_reference_ip = None;
            }

            // skip rule if it doesn't match the current scope
            if !scope.rule_address_pair_in_scope(source_ip, dest_ip) {
                continue;
            }

            // Create rule for current address combination.
            let mut current_rule = Rule::new(device_chain);
            // Match for protocol. To do this, we need to differentiate between IPv4 and IPv6.
            if let Some(ipaddr) = protocol_reference_ip {
                nf_match_l3proto(&mut current_rule, scope, &ipaddr.into());
                nf_match_l4proto(&mut current_rule, &ipaddr.into(), &rule_spec.l4_matches);
            }
            // Create expressions to match source IP.
            match source_ip {
                RuleAddrEntry::AddrEntry(device_addr) => {
                    nf_match_addresses(&mut current_rule, device_addr, &AddressMatchOn::Src);
                },
                RuleAddrEntry::AnyAddr => {},
            }
            // Create expressions to match destination IP.
            match dest_ip {
                RuleAddrEntry::AddrEntry(device_addr) => {
                    nf_match_addresses(&mut current_rule, device_addr, &AddressMatchOn::Dest);
                },
                RuleAddrEntry::AnyAddr => {},
            }
            // Create expressions to match for port numbers.
            nf_match_l4payload(
                &mut current_rule,
                rule_spec,
                &protocol_reference_ip.map(FirewallRuleProto::from),
            );

            // Set verdict if current rule matches.
            match rule_spec.verdict {
                Verdict::Accept => current_rule.add_expr(&nft_expr!(verdict accept)),
                Verdict::Reject => {
                    current_rule.add_expr(&VerdictExpr::Reject(RejectionType::Icmp(IcmpCode::AdminProhibited)));
                },
                Verdict::Drop => current_rule.add_expr(&nft_expr!(verdict drop)),
                Verdict::Log(group) => current_rule.add_expr(&nft_expr!(log group group)),
            }
            device_batch.add(&current_rule, nftnl::MsgType::Add);
        }
    }
    Ok(())
}

/// Sends the supplied nftables batches to the kernel for execution.
///
/// The `table_batch` parameter should represent the "global" batch that sets the base chain and the jump rules
/// as well as the empty device chains (except for the default rejection rule), the device batches should
/// contain a command to delete the default rejection rule and insert the actual device rules.
/// Taken and adapted from [nftnl add-rules.rs](https://github.com/mullvad/nftnl-rs/blob/master/nftnl/examples/add-rules.rs).
/// Note: An error of type `IoError` due to an OS error with code 71 might not indicate a protocol
/// error but a permission error instead (either run as root or use `setcap 'cap_net_admin=+ep' /path/to/program` on the built binary.
/// For information on how to debug, see [Debugging Netlink Sockets](http://0x90.at/post/netlink-debugging).
#[cfg(feature = "nftables")]
fn send_and_process(table_batch: &FinalizedBatch, device_batches: &[FinalizedBatch]) -> Result<()> {
    // Create a netlink socket to netfilter.
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;

    let portid = socket.portid();
    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let mut seq_num = 0;
    let mut return_value = Ok(());

    send_and_process_batch(table_batch, &socket, portid, &mut buffer, &mut seq_num)?;

    for current_batch in device_batches {
        return_value = return_value.and(send_and_process_batch(
            current_batch,
            &socket,
            portid,
            &mut buffer,
            &mut seq_num,
        ));
    }

    return_value
}

/// Sends a single nftables batch to the kernel for execution
/// Used by `send_and_process` and adapted from [add-rules.rs in nftnl-rs](https://github.com/mullvad/nftnl-rs/blob/master/nftnl/examples/add-rules.rs)
#[cfg(feature = "nftables")]
fn send_and_process_batch(
    batch: &FinalizedBatch,
    socket: &mnl::Socket,
    portid: u32,
    buffer: &mut [u8],
    seq_num: &mut u32,
) -> Result<()> {
    // Send all the bytes in the batch one by one.
    for batch_part in batch {
        socket.send(batch_part)?;
        // Wait for sent part of batch to be received properly before sending next batch part.
        // This is needed to prevent some buffer overruns.
        // This fix was actually mentioned in another issue in another project that uses the netlink API:
        // https://github.com/acassen/keepalived/issues/392#issuecomment-239609235
        loop {
            match socket_recv(socket, buffer) {
                Ok(Some(message)) => {
                    match mnl::cb_run(message, *seq_num, portid) {
                        Ok(mnl::CbResult::Stop) => {
                            break;
                        },
                        Ok(mnl::CbResult::Ok) => (),
                        Err(e) => {
                            return Err(e.into());
                        },
                    }
                    *seq_num += 1;
                },
                Err(e) => {
                    return Err(e);
                },
                _ => {
                    break;
                },
            }
        }
    }
    Ok(())
}

/// Helper function for `send_and_process()`.
/// Taken from [add-rules.rs in nftnl-rs](https://github.com/mullvad/nftnl-rs/blob/master/nftnl/examples/add-rules.rs)
#[cfg(feature = "nftables")]
fn socket_recv<'a>(socket: &mnl::Socket, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>> {
    let ret = socket.recv(buf)?;
    if ret > 0 {
        Ok(Some(&buf[..ret]))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};
    use serial_test::serial;
    use std::process::Command;

    use super::*;
    use crate::services::dns::DnsService;
    use namib_shared::firewall_config::{ScopeConstraint, TcpMatches};

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
