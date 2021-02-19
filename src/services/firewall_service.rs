use namib_shared::config_firewall::{EnTarget, FirewallConfig, FirewallRule, NetworkHost, Protocol};

use crate::{
    error::Result,
    models::model_firewall::FirewallConfigState,
    services::{dns::DnsWatcher, is_system_mode, state::EnforcerState},
    uci::UCI,
};
use nftnl::{
    expr::{IcmpCode, RejectionType, Verdict},
    nft_expr,
    set::Set,
    Batch, Chain, FinalizedBatch, ProtoFamily, Rule, Table,
};
use std::{ffi::CString, net::IpAddr, sync::Arc};
use tokio::{
    select,
    sync::{Mutex, Notify},
};
use trust_dns_resolver::AsyncResolver;

/// This file represent the service for firewall on openwrt.
///
/// Created on 11.11.2020.
///
/// @author Namib Group 3.

/// The folder where the configuration file should be stored.
const CONFIG_DIR: &str = "config";
const SAVE_DIR: &str = "/tmp/.uci_namib";
const TABLE_NAME: &str = "namib";
const BASE_CHAIN_NAME: &str = "base_chain";

pub struct FirewallService {
    dns_watcher: Arc<DnsWatcher>,
    enforcer_state: Arc<EnforcerState>,
    change_notify: Notify,
}

/// Helper enum for rule conversion.
enum RuleAddrEntry {
    AnyAddr,
    AddrEntry(IpAddr),
}

impl From<IpAddr> for RuleAddrEntry {
    fn from(a: IpAddr) -> Self {
        RuleAddrEntry::AddrEntry(a)
    }
}

impl FirewallService {
    /// Creates a new FirewallService instance with the given enforcer state and dns watcher (generated from the dns service).
    pub(crate) fn new(enforcer_state: Arc<EnforcerState>, mut watcher: DnsWatcher) -> FirewallService {
        FirewallService {
            enforcer_state,
            dns_watcher: Arc::new(watcher),
            change_notify: Notify::new(),
        }
    }

    /// Updates the current firewall config with a new value and notifies the firewall change watcher to update the firewall config.
    pub async fn apply_new_config(&self, mut config: FirewallConfig) {
        *self.enforcer_state.firewall_cfg.write().await = Some(config);
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
                .unwrap_or_else(|e| error!("An error occurred while updating the firewall configuration: {}", e));
        }
    }

    /// Updates the nftables rules to reflect the current firewall config.
    async fn apply_current_config(&self) -> Result<()> {
        debug!("Configuration has changed, applying new rules to nftables");
        let config_lock = self.enforcer_state.firewall_cfg.read().await;
        let config = config_lock.as_ref().unwrap();
        let mut batch = Batch::new();
        self.add_old_config_deletion_instructions(&mut batch)?;
        self.convert_config_to_nftnl_commands(&mut batch, &config).await?;
        let batch = batch.finalize();
        // TODO proper error handling
        send_and_process(&batch).unwrap();

        Ok(())
    }

    /// Creates nftnl expressions which delete the current namib firewall table if it exists and adds them to the given batch.
    fn add_old_config_deletion_instructions(&self, batch: &mut Batch) -> Result<()> {
        // Create the table if it doesn't exist, otherwise removing the table might cause a NotFound error.
        // If the table already exists, this doesn't do anything.
        let table = Table::new(&CString::new(TABLE_NAME).unwrap(), ProtoFamily::Inet);
        batch.add(&table, nftnl::MsgType::Add);
        // Delete the table.
        let table = Table::new(&CString::new(TABLE_NAME).unwrap(), ProtoFamily::Inet);
        batch.add(&table, nftnl::MsgType::Del);
        Ok(())
    }

    /// Converts the given firewall config into nftnl expressions and applies them to the supplied batch.
    async fn convert_config_to_nftnl_commands(&self, batch: &mut Batch, config: &FirewallConfig) -> Result<()> {
        // Create new firewall table.
        let table = Table::new(&CString::new(TABLE_NAME).unwrap(), ProtoFamily::Inet);
        batch.add(&table, nftnl::MsgType::Add);

        // Create base chain. This base chain is the entry point for the firewall table and will redirect all
        // packets corresponding to a configured device in the firewall config to its separate chain.
        let mut base_chain = Chain::new(&CString::new(BASE_CHAIN_NAME).unwrap(), &table);
        base_chain.set_hook(nftnl::Hook::In, 0);
        // If a device is not one of the configured devices, accept packets by default.
        base_chain.set_policy(nftnl::Policy::Accept);
        batch.add(&base_chain, nftnl::MsgType::Add);

        // Iterate over all devices.
        for device in config.devices() {
            // Create chain which is responsible for deciding how packets for/from this device will be treated.
            let mut device_chain = Chain::new(&CString::new(format!("device_{}", device.id)).unwrap(), &table);
            batch.add(&device_chain, nftnl::MsgType::Add);

            // Create two rules in the base chain, one for packets coming from the device and one for packets going to the device.
            let mut device_jump_rule_src = Rule::new(&base_chain);
            device_jump_rule_src.add_expr(&nft_expr!(meta nfproto));
            let mut device_jump_rule_dst = Rule::new(&base_chain);
            device_jump_rule_dst.add_expr(&nft_expr!(meta nfproto));
            // Match rule if source or target address is configured device.
            match device.ip {
                IpAddr::V4(v4addr) => {
                    device_jump_rule_src.add_expr(&nft_expr!(meta nfproto));
                    device_jump_rule_src.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV4 as u8));
                    device_jump_rule_src.add_expr(&nft_expr!(payload ipv4 saddr));
                    device_jump_rule_src.add_expr(&nft_expr!(cmp == v4addr));
                    device_jump_rule_dst.add_expr(&nft_expr!(meta nfproto));
                    device_jump_rule_dst.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV4 as u8));
                    device_jump_rule_dst.add_expr(&nft_expr!(payload ipv4 daddr));
                    device_jump_rule_dst.add_expr(&nft_expr!(cmp == v4addr));
                },
                IpAddr::V6(v6addr) => {
                    device_jump_rule_src.add_expr(&nft_expr!(meta nfproto));
                    device_jump_rule_src.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV6 as u8));
                    device_jump_rule_src.add_expr(&nft_expr!(payload ipv6 saddr));
                    device_jump_rule_src.add_expr(&nft_expr!(cmp == v6addr));
                    device_jump_rule_dst.add_expr(&nft_expr!(meta nfproto));
                    device_jump_rule_dst.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV6 as u8));
                    device_jump_rule_dst.add_expr(&nft_expr!(payload ipv6 daddr));
                    device_jump_rule_dst.add_expr(&nft_expr!(cmp == v6addr));
                },
            }
            // If these rules apply, jump to the chain responsible for handling this device.
            device_jump_rule_src
                .add_expr(&nft_expr!(verdict jump CString::new(format!("device_{}", device.id)).unwrap()));
            device_jump_rule_dst
                .add_expr(&nft_expr!(verdict jump CString::new(format!("device_{}", device.id)).unwrap()));
            batch.add(&device_jump_rule_src, nftnl::MsgType::Add);
            batch.add(&device_jump_rule_dst, nftnl::MsgType::Add);

            // Iterate over device rules.
            for rule_spec in &device.rules {
                // Depending on the type of host identifier (hostname, IP address or placeholder for device IP)
                // for the packet source or destination, create a vector of ip addresses for this identifier.
                let source_ips: Vec<RuleAddrEntry> = match &rule_spec.src.host {
                    Some(NetworkHost::Ip(ipaddr)) => {
                        vec![RuleAddrEntry::AddrEntry(ipaddr.clone())]
                    },
                    // Error handling: If host resolution fails, return an empty Vec. This will cause no rules
                    // to be generated for the supplied host (which will then default to being rejected if no other rule matches).
                    Some(NetworkHost::Hostname { dns_name, resolved_ip }) => self
                        .dns_watcher
                        .resolve_and_watch(dns_name.as_str())
                        .await
                        .map(|v| v.iter().map(|v| RuleAddrEntry::from(v)).collect())
                        .unwrap_or(Vec::new()),
                    Some(NetworkHost::FirewallDevice) => vec![RuleAddrEntry::AddrEntry(device.ip)],
                    _ => vec![RuleAddrEntry::AnyAddr],
                };
                let dest_ips: Vec<RuleAddrEntry> = match &rule_spec.dst.host {
                    Some(NetworkHost::Ip(ipaddr)) => {
                        vec![RuleAddrEntry::AddrEntry(ipaddr.clone())]
                    },
                    // Error handling: If host resolution fails, return an empty Vec. This will cause no rules
                    // to be generated for the supplied host (which will then default to being rejected if no other rule matches).
                    Some(NetworkHost::Hostname { dns_name, resolved_ip }) => self
                        .dns_watcher
                        .resolve_and_watch(dns_name.as_str())
                        .await
                        .map(|v| v.iter().map(|v| RuleAddrEntry::from(v)).collect())
                        .unwrap_or(Vec::new()),
                    Some(NetworkHost::FirewallDevice) => vec![RuleAddrEntry::AddrEntry(device.ip)],
                    _ => vec![RuleAddrEntry::AnyAddr],
                };

                // Create a rule for each source/destination ip combination.
                // Ideally, we would instead used nftnl sets, but these currently have the limitation that they
                // can only either contain IPv4 or IPv6 addresses, not both. Also, nftnl-rs does not support anonymous
                // sets yet.
                for source_ip in &source_ips {
                    for dest_ip in &dest_ips {
                        let protocol_reference_ip;
                        // Do not create rules which mix IPv4 and IPV6 addresses. Also, save at least one specified IP to match for protocol later on.
                        if let &RuleAddrEntry::AddrEntry(saddr) = source_ip {
                            if let RuleAddrEntry::AddrEntry(daddr) = dest_ip {
                                if (saddr.is_ipv4() && daddr.is_ipv4()) || (daddr.is_ipv6() && saddr.is_ipv6()) {
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
                                current_rule.add_expr(&nft_expr!(meta nfproto));
                                current_rule.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV4 as u8));
                                current_rule.add_expr(&nft_expr!(payload ipv4 saddr));
                                current_rule.add_expr(&nft_expr!(cmp == v4addr.clone()));
                            },
                            RuleAddrEntry::AddrEntry(IpAddr::V6(v6addr)) => {
                                current_rule.add_expr(&nft_expr!(meta nfproto));
                                current_rule.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV6 as u8));
                                current_rule.add_expr(&nft_expr!(payload ipv6 saddr));
                                current_rule.add_expr(&nft_expr!(cmp == v6addr.clone()));
                            },
                            RuleAddrEntry::AnyAddr => {},
                        }
                        // Create expressions to match destination IP.
                        match dest_ip {
                            RuleAddrEntry::AddrEntry(IpAddr::V4(v4addr)) => {
                                current_rule.add_expr(&nft_expr!(meta nfproto));
                                current_rule.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV4 as u8));
                                current_rule.add_expr(&nft_expr!(payload ipv4 daddr));
                                current_rule.add_expr(&nft_expr!(cmp == v4addr.clone()));
                            },
                            RuleAddrEntry::AddrEntry(IpAddr::V6(v6addr)) => {
                                current_rule.add_expr(&nft_expr!(meta nfproto));
                                current_rule.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV6 as u8));
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
                        match rule_spec.target {
                            EnTarget::ACCEPT => current_rule.add_expr(&nft_expr!(verdict accept)),
                            EnTarget::REJECT => {
                                current_rule.add_expr(&Verdict::Reject(RejectionType::Icmp(IcmpCode::AdminProhibited)))
                            },
                            EnTarget::DROP => current_rule.add_expr(&nft_expr!(verdict drop)),
                        }
                        batch.add(&current_rule, nftnl::MsgType::Add);
                    }
                }
            }
        }

        Ok(())
    }
}

/// Sends the supplied expression batch to nftables for execution.
/// Taken from https://github.com/mullvad/nftnl-rs/blob/master/nftnl/examples/add-rules.rs
/// Note: An error of type IoError due to an OS error with code 71 might not indicate a protocol
/// error but a permission error instead.
/// For information on how to debug, see http://0x90.at/post/netlink-debugging
fn send_and_process(batch: &FinalizedBatch) -> Result<()> {
    // Create a netlink socket to netfilter.
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
    // Send all the bytes in the batch.
    socket.send_all(batch)?;

    // Try to parse the messages coming back from netfilter. This part is still very unclear.
    let portid = socket.portid();
    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let very_unclear_what_this_is_for = 2;
    while let Some(message) = socket_recv(&socket, &mut buffer[..])? {
        match mnl::cb_run(message, very_unclear_what_this_is_for, portid)? {
            mnl::CbResult::Stop => {
                break;
            },
            mnl::CbResult::Ok => (),
        }
    }
    Ok(())
}

/// Helper function for send_and_process().
/// Taken from https://github.com/mullvad/nftnl-rs/blob/master/nftnl/examples/add-rules.rs
fn socket_recv<'a>(socket: &mnl::Socket, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>> {
    let ret = socket.recv(buf)?;
    if ret > 0 {
        Ok(Some(&buf[..ret]))
    } else {
        Ok(None)
    }
}
