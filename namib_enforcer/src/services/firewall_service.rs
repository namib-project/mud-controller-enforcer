// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(feature = "nftables")]
use std::ffi::CString;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use namib_shared::firewall_config::{FirewallDevice, FirewallRule};
#[cfg(feature = "nftables")]
use namib_shared::{
    firewall_config::{Protocol, RuleTargetHost, Verdict},
    EnforcerConfig,
};
#[cfg(feature = "nftables")]
use nftnl::{
    expr::{IcmpCode, RejectionType, Verdict as VerdictExpr},
    nft_expr, Batch, Chain, FinalizedBatch, ProtoFamily, Rule, Table,
};
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
const TABLE_NAME_LOCAL: &str = "namib_local";
const BASE_CHAIN_NAME: &str = "base_chain";
const BASE_CHAIN_NAME_LOCAL: &str = "base_chain";

const NF_INET_IPV4 : u8 = libc::NFPROTO_IPV4 as u8;
const NF_INET_IPV6 : u8 = libc::NFPROTO_IPV6 as u8;
const NF_BRIDGE_IPV4 : u16 = (libc::ETH_P_IP as u16).swap_bytes();
const NF_BRIDGE_IPV6 : u16 = (libc::ETH_P_IPV6 as u16).swap_bytes();

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
#[derive(Debug, Clone)]
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
        apply_firewall_config_inner(&config, &self.dns_watcher).await
    }
}

#[derive(PartialEq)]
enum FirewallRuleScope {
    Global,
    Local,
}

enum FirewallRuleProto {
    IPv4,
    IPv6,
}

#[cfg(feature = "nftables")]
pub(crate) async fn apply_firewall_config_inner(config: &EnforcerConfig, dns_watcher: &DnsWatcher) -> Result<()> {
    for scope in [FirewallRuleScope::Global, FirewallRuleScope::Local] {
        debug!("Creating rules for table {}", match scope {FirewallRuleScope::Local => TABLE_NAME_LOCAL, FirewallRuleScope::Global => TABLE_NAME});
        let mut batch = Batch::new();
        add_old_config_deletion_instructions(&mut batch, &scope);
        let mut device_batches = Vec::new();
        convert_config_to_nftnl_commands(&mut batch, &config, &scope, dns_watcher, &mut device_batches).await?;
        let batch = batch.finalize();
        debug!("Applying rules for table {}", match scope {FirewallRuleScope::Local => TABLE_NAME_LOCAL, FirewallRuleScope::Global => TABLE_NAME});
        if let Err(e) = send_and_process(batch, &device_batches) {
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

/// Creates nftnl expressions which delete the current namib firewall table if it exists and adds them to the given batch.
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
        FirewallRuleScope::Global => Table::new(&CString::new(TABLE_NAME).unwrap(), ProtoFamily::Inet),
        FirewallRuleScope::Local => Table::new(&CString::new(TABLE_NAME_LOCAL).unwrap(), ProtoFamily::Bridge),
    }
}

// Adds netfilter instructions to match ipv4 or ipv6 protocol in rule.
#[cfg(feature = "nftables")]
fn nf_match_proto(rule: &mut Rule, scope: &FirewallRuleScope, proto: &FirewallRuleProto) {
    match scope {
        FirewallRuleScope::Global => {
            rule.add_expr(&nft_expr!(meta nfproto));
            match proto {
                FirewallRuleProto::IPv4 => {rule.add_expr(&nft_expr!(cmp == NF_INET_IPV4));},
                FirewallRuleProto::IPv6 => {rule.add_expr(&nft_expr!(cmp == NF_INET_IPV6));},
            }
        },
        FirewallRuleScope::Local => {
            rule.add_expr(&nft_expr!(meta proto));
            match proto {
                FirewallRuleProto::IPv4 => {rule.add_expr(&nft_expr!(cmp == NF_BRIDGE_IPV4));},
                FirewallRuleProto::IPv6 => {rule.add_expr(&nft_expr!(cmp == NF_BRIDGE_IPV6));},
            }
        },
    }
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
        FirewallRuleScope::Global => BASE_CHAIN_NAME,
        FirewallRuleScope::Local => BASE_CHAIN_NAME_LOCAL,
    };
    let mut base_chain = Chain::new(&CString::new(base_chain_name).unwrap(), &table);
    let base_chain_hook = match scope {
        FirewallRuleScope::Global => nftnl::Hook::Forward,
        FirewallRuleScope::Local => nftnl::Hook::In,
    };
    base_chain.set_hook(base_chain_hook, 0);
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

        if let Some(v4addr) = device.ipv4_addr {
            // Create two rules in the base chain, one for packets coming from the device and one for packets going to the device.
            let mut device_jump_rule_src = Rule::new(&base_chain);
            let mut device_jump_rule_dst = Rule::new(&base_chain);
            // Match rule if source or target address is configured device.
            nf_match_proto(&mut device_jump_rule_src, scope, &FirewallRuleProto::IPv4);
            device_jump_rule_src.add_expr(&nft_expr!(payload ipv4 saddr));
            device_jump_rule_src.add_expr(&nft_expr!(cmp == v4addr));
            nf_match_proto(&mut device_jump_rule_dst, scope, &FirewallRuleProto::IPv4);
            device_jump_rule_dst.add_expr(&nft_expr!(payload ipv4 daddr));
            device_jump_rule_dst.add_expr(&nft_expr!(cmp == v4addr));
            // If these rules apply, jump to the chain responsible for handling this device.
            device_jump_rule_src
                .add_expr(&nft_expr!(verdict jump CString::new(format!("device_{}", device.id)).unwrap()));
            device_jump_rule_dst
                .add_expr(&nft_expr!(verdict jump CString::new(format!("device_{}", device.id)).unwrap()));
            batch.add(&device_jump_rule_src, nftnl::MsgType::Add);
            batch.add(&device_jump_rule_dst, nftnl::MsgType::Add);
        }
        if let Some(v6addr) = device.ipv6_addr {
            // Create two rules in the base chain, one for packets coming from the device and one for packets going to the device.
            let mut device_jump_rule_src = Rule::new(&base_chain);
            let mut device_jump_rule_dst = Rule::new(&base_chain);
            // Match rule if source or target address is configured device.
            nf_match_proto(&mut device_jump_rule_src, scope, &FirewallRuleProto::IPv6);
            device_jump_rule_src.add_expr(&nft_expr!(payload ipv6 saddr));
            device_jump_rule_src.add_expr(&nft_expr!(cmp == v6addr));
            nf_match_proto(&mut device_jump_rule_dst, scope, &FirewallRuleProto::IPv6);
            device_jump_rule_dst.add_expr(&nft_expr!(payload ipv6 daddr));
            device_jump_rule_dst.add_expr(&nft_expr!(cmp == v6addr));
            // If these rules apply, jump to the chain responsible for handling this device.
            device_jump_rule_src
                .add_expr(&nft_expr!(verdict jump CString::new(format!("device_{}", device.id)).unwrap()));
            device_jump_rule_dst
                .add_expr(&nft_expr!(verdict jump CString::new(format!("device_{}", device.id)).unwrap()));
            batch.add(&device_jump_rule_src, nftnl::MsgType::Add);
            batch.add(&device_jump_rule_dst, nftnl::MsgType::Add);
        }

        // Iterate over device rules.
        for rule_spec in &device.rules {
            add_rule_to_batch(&device_chain, &mut device_batch, &device, &scope, &rule_spec, dns_watcher).await?;
        }
        device_batches.push(device_batch.finalize());
    }

    Ok(())
}

/// Adds a rule based on the given rule_spec to the given device_batch as part of the given device_chain
#[cfg(feature = "nftables")]
async fn add_rule_to_batch(
    device_chain: &Chain<'_>,
    device_batch: &mut Batch,
    device: &FirewallDevice,
    scope: &FirewallRuleScope,
    rule_spec: &FirewallRule,
    dns_watcher: &DnsWatcher,
) -> Result<()> {
    // Depending on the type of host identifier (hostname, IP address or placeholder for device IP)
    // for the packet source or destination, create a vector of ip addresses for this identifier.
    let source_ips: Vec<RuleAddrEntry> = match &rule_spec.src.host {
        Some(RuleTargetHost::Ip(ipaddr)) => {
            vec![RuleAddrEntry::AddrEntry(ipaddr.clone())]
        },
        // Error handling: If host resolution fails, return an empty Vec. This will cause no rules
        // to be generated for the supplied host (which will then default to being rejected if no other rule matches).
        Some(RuleTargetHost::Hostname(dns_name)) => dns_watcher
            .resolve_and_watch(dns_name.as_str())
            .await
            .map(|v| v.iter().map(|v| RuleAddrEntry::from(v)).collect())
            .unwrap_or(Vec::new()),
        Some(RuleTargetHost::FirewallDevice) => device
            .ipv4_addr
            .map(RuleAddrEntry::from)
            .into_iter()
            .chain(device.ipv6_addr.into_iter().map(RuleAddrEntry::from))
            .collect(),
        _ => vec![RuleAddrEntry::AnyAddr],
    };
    let dest_ips: Vec<RuleAddrEntry> = match &rule_spec.dst.host {
        Some(RuleTargetHost::Ip(ipaddr)) => {
            vec![RuleAddrEntry::AddrEntry(ipaddr.clone())]
        },
        // Error handling: If host resolution fails, return an empty Vec. This will cause no rules
        // to be generated for the supplied host (which will then default to being rejected if no other rule matches).
        Some(RuleTargetHost::Hostname(dns_name)) => dns_watcher
            .resolve_and_watch(dns_name.as_str())
            .await
            .map(|v| v.iter().map(|v| RuleAddrEntry::from(v)).collect())
            .unwrap_or(Vec::new()),
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
            // Create rule for current address combination.
            let mut current_rule = Rule::new(&device_chain);
            // Match for protocol. To do this, we need to differentiate between IPv4 and IPv6.
            match protocol_reference_ip {
                Some(IpAddr::V4(_v4addr)) => {
                    // Match for protocol.
                    match rule_spec.protocol {
                        Protocol::Tcp => {
                            current_rule.add_expr(&nft_expr!(payload ipv4 protocol));
                            current_rule.add_expr(&nft_expr!(cmp == "tcp"));
                        },
                        Protocol::Udp => {
                            current_rule.add_expr(&nft_expr!(payload ipv4 protocol));
                            current_rule.add_expr(&nft_expr!(cmp == "udp"));
                        },
                        _ => {}, // TODO expand with further options (icmp, sctp)
                    }
                },
                Some(IpAddr::V6(_v6addr)) => {
                    match rule_spec.protocol {
                        Protocol::Tcp => {
                            current_rule.add_expr(&nft_expr!(payload ipv6 nextheader));
                            current_rule.add_expr(&nft_expr!(cmp == "tcp"));
                        },
                        Protocol::Udp => {
                            current_rule.add_expr(&nft_expr!(payload ipv6 nextheader));
                            current_rule.add_expr(&nft_expr!(cmp == "udp"));
                        },
                        _ => {}, // TODO expand with further options (icmp, sctp)
                    }
                },
                _ => {},
            }
            // Create expressions to match source IP.
            match source_ip {
                RuleAddrEntry::AddrEntry(IpAddr::V4(v4addr)) => {
                    nf_match_proto(&mut current_rule, &scope, &FirewallRuleProto::IPv4);
                    current_rule.add_expr(&nft_expr!(payload ipv4 saddr));
                    current_rule.add_expr(&nft_expr!(cmp == v4addr.clone()));
                },
                RuleAddrEntry::AddrEntry(IpAddr::V6(v6addr)) => {
                    nf_match_proto(&mut current_rule, &scope, &FirewallRuleProto::IPv6);
                    current_rule.add_expr(&nft_expr!(payload ipv6 saddr));
                    current_rule.add_expr(&nft_expr!(cmp == v6addr.clone()));
                },
                RuleAddrEntry::AnyAddr => {},
            }
            // Create expressions to match destination IP.
            match dest_ip {
                RuleAddrEntry::AddrEntry(IpAddr::V4(v4addr)) => {
                    nf_match_proto(&mut current_rule, &scope, &FirewallRuleProto::IPv4);
                    current_rule.add_expr(&nft_expr!(payload ipv4 daddr));
                    current_rule.add_expr(&nft_expr!(cmp == v4addr.clone()));
                },
                RuleAddrEntry::AddrEntry(IpAddr::V6(v6addr)) => {
                    nf_match_proto(&mut current_rule, &scope, &FirewallRuleProto::IPv6);
                    current_rule.add_expr(&nft_expr!(payload ipv6 daddr));
                    current_rule.add_expr(&nft_expr!(cmp == v6addr.clone()));
                },
                RuleAddrEntry::AnyAddr => {},
            }
            // Create expressions to match for port numbers.
            match rule_spec.protocol {
                Protocol::Tcp => {
                    if let Some(port) = &rule_spec.dst.port {
                        current_rule.add_expr(&nft_expr!(payload tcp dport));
                        current_rule.add_expr(&nft_expr!(cmp == port.as_str()));
                    }
                    if let Some(port) = &rule_spec.src.port {
                        current_rule.add_expr(&nft_expr!(payload tcp dport));
                        current_rule.add_expr(&nft_expr!(cmp == port.as_str()));
                    }
                },
                Protocol::Udp => {
                    if let Some(port) = &rule_spec.dst.port {
                        current_rule.add_expr(&nft_expr!(payload udp dport));
                        current_rule.add_expr(&nft_expr!(cmp == port.as_str()));
                    }
                    if let Some(port) = &rule_spec.src.port {
                        current_rule.add_expr(&nft_expr!(payload udp dport));
                        current_rule.add_expr(&nft_expr!(cmp == port.as_str()));
                    }
                },
                _ => {},
            }

            // Set verdict if current rule matches.
            match rule_spec.verdict {
                Verdict::Accept => current_rule.add_expr(&nft_expr!(verdict accept)),
                Verdict::Reject => {
                    current_rule.add_expr(&VerdictExpr::Reject(RejectionType::Icmp(IcmpCode::AdminProhibited)))
                },
                Verdict::Drop => current_rule.add_expr(&nft_expr!(verdict drop)),
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
/// Taken and adapted from https://github.com/mullvad/nftnl-rs/blob/master/nftnl/examples/add-rules.rs
/// Note: An error of type IoError due to an OS error with code 71 might not indicate a protocol
/// error but a permission error instead (either run as root or use `setcap 'cap_net_admin=+ep' /path/to/program` on the built binary.
/// For information on how to debug, see http://0x90.at/post/netlink-debugging
#[cfg(feature = "nftables")]
fn send_and_process(table_batch: FinalizedBatch, device_batches: &[FinalizedBatch]) -> Result<()> {
    // Create a netlink socket to netfilter.
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;

    let portid = socket.portid();
    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let mut seq_num = 0;
    let mut return_value = Ok(());

    send_and_process_batch(&table_batch, &socket, portid, &mut buffer, &mut seq_num)?;

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
/// Used by send_and_process and adapted from https://github.com/mullvad/nftnl-rs/blob/master/nftnl/examples/add-rules.rs
#[cfg(feature = "nftables")]
fn send_and_process_batch(
    batch: &FinalizedBatch,
    socket: &mnl::Socket,
    portid: u32,
    buffer: &mut [u8],
    seq_num: &mut u32,
) -> Result<()> {
    // Send all the bytes in the batch one by one.
    let mut batch_iter = batch.iter();
    while let Some(batch_part) = batch_iter.next() {
        socket.send(batch_part)?;
        // Wait for sent part of batch to be received properly before sending next batch part.
        // This is needed to prevent some buffer overruns.
        // This fix was actually mentioned in another issue in another project that uses the netlink API:
        // https://github.com/acassen/keepalived/issues/392#issuecomment-239609235
        loop {
            match socket_recv(&socket, buffer) {
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
                    return Err(e.into());
                },
                _ => {
                    break;
                },
            }
        }
    }
    Ok(())
}

/// Helper function for send_and_process().
/// Taken from https://github.com/mullvad/nftnl-rs/blob/master/nftnl/examples/add-rules.rs
#[cfg(feature = "nftables")]
fn socket_recv<'a>(socket: &mnl::Socket, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>> {
    let ret = socket.recv(buf)?;
    if ret > 0 {
        Ok(Some(&buf[..ret]))
    } else {
        Ok(None)
    }
}
