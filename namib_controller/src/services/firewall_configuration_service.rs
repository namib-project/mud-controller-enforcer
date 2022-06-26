// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach, Jan Hensel, Hannes Masuch
// SPDX-License-Identifier: MIT OR Apache-2.0

use chrono::NaiveDateTime;
use std::net::IpAddr;

use namib_shared::{
    firewall_config::{FirewallDevice, FirewallRule, PortOrRange, RuleTargetHost, ScopeConstraint, Verdict},
    flow_scope::LogGroup,
    EnforcerConfig,
};

use crate::{
    db::DbConnection,
    error::Result,
    models::{
        other_device_by_direction, AceAction, AcePort, AceProtocol, Acl, AclDirection, AclType, AdministrativeContext,
        ConfiguredControllerMapping, DefinedServer, DeviceWithRefs, FlowScopeLevel, IcmpMatches, Ipv4HeaderFlags,
        L3Matches, L4Matches, TcpHeaderFlags, TcpMatches, TcpOptions, UdpMatches,
    },
    services::{
        acme_service,
        config_service::{get_config_value, set_config_value, ConfigKeys},
    },
};

pub fn create_configuration(
    version: String,
    devices: &[DeviceWithRefs],
    administrative_context: &AdministrativeContext,
    next_expiration: &Option<NaiveDateTime>,
) -> EnforcerConfig {
    let mut rules = vec![];
    for device in devices
        .iter()
        .filter(|d| d.ipv4_addr.is_some() || d.ipv6_addr.is_some())
    {
        let mut result = convert_device_to_fw_rules(device, devices, administrative_context);
        let mut scope_rules = get_flow_scope_rules(device);
        // Flow scope rules come first, before any accept/drop
        scope_rules.extend(result.rules);
        result.rules = scope_rules;
        rules.push(result);
    }

    EnforcerConfig::new(version, rules, acme_service::DOMAIN.clone(), *next_expiration)
}

pub fn convert_device_to_fw_rules(
    device: &DeviceWithRefs,
    devices: &[DeviceWithRefs],
    administrative_context: &AdministrativeContext,
) -> FirewallDevice {
    let mut rule_counter = 0;
    let mut rules: Vec<FirewallRule> = Vec::new();
    if device.q_bit {
        for exception in &device.quarantine_exceptions {
            let exception_target = match exception.exception_target.parse::<IpAddr>() {
                Ok(addr) => RuleTargetHost::Ip(addr),
                Err(_) => RuleTargetHost::Hostname(exception.exception_target.clone()),
            };
            let (src, dst) = match exception.direction {
                AclDirection::FromDevice => (Some(RuleTargetHost::FirewallDevice), Some(exception_target)),
                AclDirection::ToDevice => (Some(exception_target), Some(RuleTargetHost::FirewallDevice)),
            };
            rules.push(FirewallRule::new(
                format!("rule_quarantine_exception_{}", rule_counter),
                src,
                dst,
                None,
                None,
                Verdict::Accept,
                ScopeConstraint::None,
            ));
            rule_counter += 1;
        }
    } else if let Some(mud_data) = &device.mud_data {
        let merged_acls = if mud_data.acl_override.is_empty() {
            mud_data.acllist.iter().collect()
        } else {
            merge_acls(&mud_data.acllist, &mud_data.acl_override)
        };

        for acl in &merged_acls {
            for ace in &acl.ace {
                let verdict = match ace.action {
                    AceAction::Accept => Verdict::Accept,
                    AceAction::Deny => Verdict::Reject,
                };
                let mut scope = ScopeConstraint::None;

                let mut l4_matchable: Option<namib_shared::firewall_config::L4Matches> =
                    ace.matches.l4.clone().map(std::convert::Into::into);
                let l3_matchable: Option<namib_shared::firewall_config::L3MatchesExtra> =
                    convert_l3_matches_info(&ace.matches.l3);

                // NOTE:
                //   We check for a mismatch between:
                //   - the L4 protocol that is specified in the MUD L3 (IP) matches data
                //   - the L4 protocol for which matches data is specified
                //   This should never come up, as we consider this case in parsing the MUD data,
                //   and as an edge case it would produce a rule that would match nothing and thus
                //   have no effect.
                match (&ace.matches.l3_specified_l4_protocol(), &l4_matchable) {
                    // MUD L3 data specifies protocol but no L4 matches data
                    (Some(l4_proto), None) => { l4_matchable = match l4_proto {
                        AceProtocol::Tcp  => Some(namib_shared::firewall_config::L4Matches::empty_tcp()),
                        AceProtocol::Udp  => Some(namib_shared::firewall_config::L4Matches::empty_udp()),
                        AceProtocol::Icmp => Some(namib_shared::firewall_config::L4Matches::empty_icmp()),
                        AceProtocol::Protocol(_) => None,
                    }},
                    // no L4 protocol specified per L3 matches data
                    (None, _)
                        // L3-header-specified L4 protocol and L4 matches data protocol are the same
                        | (Some(AceProtocol::Tcp), Some(namib_shared::firewall_config::L4Matches::Tcp(_)))
                        | (Some(AceProtocol::Udp), Some(namib_shared::firewall_config::L4Matches::Udp(_)))
                        | (Some(AceProtocol::Icmp), Some(namib_shared::firewall_config::L4Matches::Icmp(_))) => {},
                    // L3-header-specified L4 protocol and L4 matches data are NOT the same
                    (Some(a), Some(b)) => {
                        warn!(
                            "MUD L3 matches data specifies L4 protocol {} but L4 matches data is for {} (DEV: (name: {:?}, url: {:?}), MUD: {:?})",
                            a.to_string(),
                            b.to_protocol_string(),
                            device.name,
                            device.mud_url,
                            mud_data,
                        );
                    },
                }

                let this_dev_rule_target = Some(RuleTargetHost::FirewallDevice);

                let dnsname: &Option<String> = if let Some(l3) = &ace.matches.l3 {
                    match l3 {
                        L3Matches::Ipv4(matches) => {
                            other_device_by_direction(&matches.src_dnsname, &matches.dst_dnsname, acl.packet_direction)
                        },
                        L3Matches::Ipv6(matches) => {
                            other_device_by_direction(&matches.src_dnsname, &matches.dst_dnsname, acl.packet_direction)
                        },
                    }
                } else {
                    &None
                };
                let other_dev_rule_targets: Vec<Option<RuleTargetHost>> = match (dnsname, &ace.matches.mud) {
                    // NOTE: `dns_name` has YANG type 'inet:host' which _can_ be an IP address
                    (Some(dns_name), None) => match dns_name.parse::<IpAddr>() {
                        Ok(addr) => vec![Some(RuleTargetHost::Ip(addr))],
                        Err(_) => vec![Some(RuleTargetHost::Hostname(dns_name.clone()))],
                    },
                    (None, Some(augmentation)) => {
                        let mut targets_per_option: Vec<Vec<Option<RuleTargetHost>>> = Vec::new();
                        if let Some(host) = &augmentation.manufacturer {
                            targets_per_option.push(get_manufacturer_ruletargethosts(host, devices, &acl.acl_type));
                        }
                        if augmentation.same_manufacturer {
                            targets_per_option.push(get_same_manufacturer_ruletargethosts(
                                device,
                                devices,
                                &acl.acl_type,
                            ));
                        }
                        if let Some(uri) = &augmentation.controller {
                            targets_per_option.push(get_controller_ruletargethosts(
                                device.mud_url.as_ref().unwrap_or(&String::from("(unknown)")).as_str(),
                                devices,
                                uri,
                                acl.acl_type,
                                &verdict,
                                administrative_context,
                            ));
                        }
                        if augmentation.my_controller {
                            targets_per_option.push(get_my_controller_ruletargethosts(
                                device,
                                devices,
                                acl.acl_type,
                                &verdict,
                                administrative_context,
                            ));
                        }
                        if augmentation.local {
                            scope = ScopeConstraint::Local;
                        }
                        if let Some(url) = &augmentation.model {
                            targets_per_option.push(get_model_ruletargethosts(url, devices, &acl.acl_type));
                        }

                        // return those devices matched by _all_ specified options
                        match targets_per_option.len() {
                            0 => vec![],
                            1 => targets_per_option[0].clone(),
                            _ => targets_per_option[0]
                                .iter()
                                .filter(|host| targets_per_option[1..].iter().all(|v| v.contains(host)))
                                .cloned()
                                .collect(),
                        }
                    },
                    _ => vec![],
                }
                .clone();

                for other_dev_rule_target in &other_dev_rule_targets {
                    let (src, dst) = match acl.packet_direction {
                        AclDirection::FromDevice => (&this_dev_rule_target, other_dev_rule_target),
                        AclDirection::ToDevice => (other_dev_rule_target, &this_dev_rule_target),
                    };
                    rules.push(FirewallRule::new(
                        format!("rule_{}", rule_counter),
                        src.clone(),
                        dst.clone(),
                        l3_matchable.clone(),
                        l4_matchable.clone(), // includes ports
                        verdict.clone(),
                        scope,
                    ));
                    rule_counter += 1;
                }
            }
        }

        for server in &administrative_context.dns_mappings {
            rules.push(FirewallRule::new(
                format!("rule_dns_default_accept_{}", rule_counter),
                Some(RuleTargetHost::FirewallDevice),
                Some(server.into()),
                None,
                Some(namib_shared::firewall_config::L4Matches::Tcp(
                    namib_shared::firewall_config::TcpMatches::only_ports(None, Some(PortOrRange::Single(53))),
                )),
                Verdict::Accept,
                ScopeConstraint::None, // NOTE(ja_he): could be `Local`; we choose to allow any user-named device
            ));
            rule_counter += 1;
            rules.push(FirewallRule::new(
                format!("rule_dns_default_accept_{}", rule_counter),
                Some(RuleTargetHost::FirewallDevice),
                Some(server.into()),
                None,
                Some(namib_shared::firewall_config::L4Matches::Udp(
                    namib_shared::firewall_config::UdpMatches::only_ports(None, Some(PortOrRange::Single(53))),
                )),
                Verdict::Accept,
                ScopeConstraint::None, // NOTE(ja_he): could be `Local`; we choose to allow any user-named device
            ));
            rule_counter += 1;
        }
        for server in &administrative_context.ntp_mappings {
            rules.push(FirewallRule::new(
                format!("rule_ntp_default_accept_{}", rule_counter),
                Some(RuleTargetHost::FirewallDevice),
                Some(server.into()),
                None,
                Some(namib_shared::firewall_config::L4Matches::Tcp(
                    namib_shared::firewall_config::TcpMatches::only_ports(None, Some(PortOrRange::Single(123))),
                )),
                Verdict::Accept,
                ScopeConstraint::None, // NOTE(ja_he): could be `Local`; we choose to allow any user-named device
            ));
            rule_counter += 1;
            rules.push(FirewallRule::new(
                format!("rule_ntp_default_accept_{}", rule_counter),
                Some(RuleTargetHost::FirewallDevice),
                Some(server.into()),
                None,
                Some(namib_shared::firewall_config::L4Matches::Udp(
                    namib_shared::firewall_config::UdpMatches::only_ports(None, Some(PortOrRange::Single(123))),
                )),
                Verdict::Accept,
                ScopeConstraint::None, // NOTE(ja_he): could be `Local`; we choose to allow any user-named device
            ));
            rule_counter += 1;
        }
    } else {
        return FirewallDevice {
            id: device.id,
            ipv4_addr: device.ipv4_addr,
            ipv6_addr: device.ipv6_addr,
            rules,
            collect_data: device.collect_info,
        };
    }
    rules.push(FirewallRule::new(
        format!("rule_default_{}", rule_counter),
        Some(RuleTargetHost::FirewallDevice),
        None,
        None,
        None,
        Verdict::Reject,
        ScopeConstraint::None,
    ));
    rule_counter += 1;
    rules.push(FirewallRule::new(
        format!("rule_default_{}", rule_counter),
        None,
        Some(RuleTargetHost::FirewallDevice),
        None,
        None,
        Verdict::Reject,
        ScopeConstraint::None,
    ));

    FirewallDevice {
        id: device.id,
        ipv4_addr: device.ipv4_addr,
        ipv6_addr: device.ipv6_addr,
        rules,
        collect_data: device.collect_info,
    }
}

pub fn get_flow_scope_rules(device_to_check: &DeviceWithRefs) -> Vec<FirewallRule> {
    device_to_check
        .flow_scopes
        .iter()
        .flat_map(|s| {
            let group = match s.level {
                FlowScopeLevel::Full => (LogGroup::FullFromDevice, LogGroup::FullToDevice),
                FlowScopeLevel::HeadersOnly => (LogGroup::HeadersOnlyFromDevice, LogGroup::HeadersOnlyToDevice),
            };
            let mut result = vec![];
            if let Some(addr) = device_to_check.ipv4_addr {
                result.push(FirewallRule::new(
                    format!("scope_{}_{}_fr4", device_to_check.id, s.name),
                    Some(RuleTargetHost::Ip(addr.into())),
                    None,
                    None,
                    None,
                    Verdict::Log(group.0.clone().into()),
                    ScopeConstraint::None,
                ));
                result.push(FirewallRule::new(
                    format!("scope_{}_{}_to4", device_to_check.id, s.name),
                    None,
                    Some(RuleTargetHost::Ip(addr.into())),
                    None,
                    None,
                    Verdict::Log(group.1.clone().into()),
                    ScopeConstraint::None,
                ));
            }
            if let Some(addr) = device_to_check.ipv6_addr {
                result.push(FirewallRule::new(
                    format!("scope_{}_{}_fr6", device_to_check.id, s.name),
                    Some(RuleTargetHost::Ip(addr.into())),
                    None,
                    None,
                    None,
                    Verdict::Log(group.0.into()),
                    ScopeConstraint::None,
                ));
                result.push(FirewallRule::new(
                    format!("scope_{}_{}_to6", device_to_check.id, s.name),
                    None,
                    Some(RuleTargetHost::Ip(addr.into())),
                    None,
                    None,
                    Verdict::Log(group.1.into()),
                    ScopeConstraint::None,
                ));
            }
            result
        })
        .collect::<Vec<FirewallRule>>()
}

pub fn merge_acls<'a>(original: &'a [Acl], override_with: &'a [Acl]) -> Vec<&'a Acl> {
    let override_keys: Vec<&str> = override_with.iter().map(|x| x.name.as_ref()).collect();
    original
        .iter()
        .filter(|x| !override_keys.contains(&x.name.as_str()))
        .chain(override_with.iter())
        .collect()
}

pub fn get_same_manufacturer_ruletargethosts(
    device_to_check: &DeviceWithRefs,
    devices: &[DeviceWithRefs],
    acl_type: &AclType,
) -> Vec<Option<RuleTargetHost>> {
    let mut manu_match: Vec<Option<RuleTargetHost>> = Vec::new();
    if let Some(device_to_check_url) = &device_to_check.mud_url {
        let device_to_check_manu = device_to_check_url.split('/').nth(2);
        for device_with_refs in devices
            .iter()
            .filter(|v| v.id != device_to_check.id && v.mud_url.is_some())
        {
            if device_to_check_manu == device_with_refs.mud_url.as_ref().unwrap().split('/').nth(2) {
                match (acl_type, &device_with_refs.ipv4_addr, &device_with_refs.ipv6_addr) {
                    (AclType::IPV4, Some(ipv4_addr), _) => {
                        manu_match.push(Some(RuleTargetHost::Ip((*ipv4_addr).into())));
                    },
                    (AclType::IPV6, _, Some(ipv6_addr)) => {
                        manu_match.push(Some(RuleTargetHost::Ip((*ipv6_addr).into())));
                    },
                    _ => {
                        manu_match.push(Some(RuleTargetHost::Hostname(device_with_refs.hostname.clone())));
                    },
                }
            }
        }
    }
    manu_match
}

pub fn get_manufacturer_ruletargethosts(
    string_to_check: &str,
    devices: &[DeviceWithRefs],
    acl_type: &AclType,
) -> Vec<Option<RuleTargetHost>> {
    let mut manu_match: Vec<Option<RuleTargetHost>> = Vec::new();
    for device_with_refs in devices.iter().filter(|v| v.mud_url.is_some()) {
        if device_with_refs.mud_url.as_ref().unwrap().split('/').nth(2) == Some(string_to_check) {
            match (acl_type, &device_with_refs.ipv4_addr, &device_with_refs.ipv6_addr) {
                (AclType::IPV4, Some(ipv4_addr), _) => {
                    manu_match.push(Some(RuleTargetHost::Ip((*ipv4_addr).into())));
                },
                (AclType::IPV6, _, Some(ipv6_addr)) => {
                    manu_match.push(Some(RuleTargetHost::Ip((*ipv6_addr).into())));
                },
                _ => {
                    manu_match.push(Some(RuleTargetHost::Hostname(device_with_refs.hostname.clone())));
                },
            }
        }
    }
    manu_match
}

pub fn get_model_ruletargethosts(
    url: &str,
    devices: &[DeviceWithRefs],
    acl_type: &AclType,
) -> Vec<Option<RuleTargetHost>> {
    let mut model_match: Vec<Option<RuleTargetHost>> = Vec::new();
    for device_with_refs in devices {
        if device_with_refs.inner.mud_url.is_some() && url.eq(device_with_refs.mud_url.as_ref().unwrap()) {
            match (acl_type, &device_with_refs.ipv4_addr, &device_with_refs.ipv6_addr) {
                (AclType::IPV4, Some(ipv4_addr), _) => {
                    model_match.push(Some(RuleTargetHost::Ip((*ipv4_addr).into())));
                },
                (AclType::IPV6, _, Some(ipv6_addr)) => {
                    model_match.push(Some(RuleTargetHost::Ip((*ipv6_addr).into())));
                },
                _ => {
                    model_match.push(Some(RuleTargetHost::Hostname(device_with_refs.hostname.clone())));
                },
            }
        }
    }
    model_match
}

fn get_my_controller_ruletargethosts(
    device: &DeviceWithRefs,
    devices: &[DeviceWithRefs],
    acl_type: AclType,
    verdict: &Verdict,
    administrative_context: &AdministrativeContext,
) -> Vec<Option<RuleTargetHost>> {
    device
        .controller_mappings
        .iter()
        .flat_map(|configured_controller_mapping| match configured_controller_mapping {
            ConfiguredControllerMapping::Ip(addr) => vec![Some(RuleTargetHost::Ip(*addr))],
            ConfiguredControllerMapping::Uri(uri) => get_controller_ruletargethosts(
                device.mud_url.as_ref().unwrap_or(&String::from("(unknown)")).as_str(),
                devices,
                uri,
                acl_type,
                verdict,
                administrative_context,
            ),
        })
        .collect()
}

fn get_controller_ruletargethosts(
    mud_url: &str,
    devices: &[DeviceWithRefs],
    controller_uri: &str,
    acl_type: AclType,
    verdict: &Verdict,
    administrative_context: &AdministrativeContext,
) -> Vec<Option<RuleTargetHost>> {
    if controller_uri.starts_with("urn:") {
        if *verdict == Verdict::Reject || *verdict == Verdict::Drop {
            warn!(
                "using a reject (or drop) verdict with a URN ({}) probably makes little sense and won't work in the NAMIB system.",
                controller_uri,
            );
        }
        match controller_uri {
            "urn:ietf:params:mud:dns" => administrative_context
                .dns_mappings
                .iter()
                .map(|server| {
                    Some(match server {
                        DefinedServer::Ip(addr) => RuleTargetHost::Ip(*addr),
                        DefinedServer::Url(url) => RuleTargetHost::Hostname(url.clone()),
                    })
                })
                .collect(),
            "urn:ietf:params:mud:ntp" => administrative_context
                .ntp_mappings
                .iter()
                .map(|server| {
                    Some(match server {
                        DefinedServer::Ip(addr) => RuleTargetHost::Ip(*addr),
                        DefinedServer::Url(url) => RuleTargetHost::Hostname(url.clone()),
                    })
                })
                .collect(),
            _ => {
                warn!(
                    "`controller` URI '{}' for device with MUD URL '{}' seems to be a URN, but not a MUD well-known URN. It is ignored.",
                    controller_uri,
                    mud_url,
                );
                vec![]
            },
        }
    } else {
        devices
            .iter()
            .filter(|other_dev| match &other_dev.mud_url {
                Some(url) => controller_uri == url,
                None => false,
            })
            .map(
                |controller_dev| match (controller_dev.ipv4_addr, controller_dev.ipv6_addr, acl_type) {
                    (Some(addr), _, AclType::IPV4) => Some(RuleTargetHost::Ip(addr.into())),
                    (_, Some(addr), AclType::IPV6) => Some(RuleTargetHost::Ip(addr.into())),
                    _ => Some(RuleTargetHost::Hostname(controller_uri.to_string())),
                },
            )
            .collect()
    }
}

pub async fn get_config_version(pool: &DbConnection) -> String {
    get_config_value(ConfigKeys::FirewallConfigVersion.as_ref(), pool)
        .await
        .unwrap_or_else(|_| "0".to_string())
}

pub async fn update_config_version(pool: &DbConnection) -> Result<()> {
    let old_config_version = get_config_value(ConfigKeys::FirewallConfigVersion.as_ref(), pool)
        .await
        .unwrap_or(0u64);
    set_config_value(
        ConfigKeys::FirewallConfigVersion.as_ref(),
        old_config_version.wrapping_add(1),
        pool,
    )
    .await?;
    Ok(())
}

impl From<AclDirection> for namib_shared::firewall_config::Direction {
    fn from(from: AclDirection) -> Self {
        match from {
            AclDirection::ToDevice => namib_shared::firewall_config::Direction::ToDevice,
            AclDirection::FromDevice => namib_shared::firewall_config::Direction::FromDevice,
        }
    }
}

impl From<AcePort> for PortOrRange {
    fn from(from: AcePort) -> Self {
        match from {
            AcePort::Single(port) => Self::Single(port as u16),
            AcePort::Range(lower, upper) => Self::Range(lower as u16, upper as u16),
        }
    }
}

impl From<TcpMatches> for namib_shared::firewall_config::TcpMatches {
    fn from(from: TcpMatches) -> Self {
        Self {
            src_port: from.src_port.map(std::convert::Into::into),
            dst_port: from.dst_port.map(std::convert::Into::into),
            sequence_number: from.sequence_number,
            acknowledgement_number: from.acknowledgement_number,
            data_offset: from.data_offset,
            reserved: from.reserved,
            flags: from.flags.map(std::convert::Into::into),
            window_size: from.window_size,
            urgent_pointer: from.urgent_pointer,
            options: from.options.map(std::convert::Into::into),
            direction_initiated: from.direction_initiated.map(std::convert::Into::into),
        }
    }
}

impl From<UdpMatches> for namib_shared::firewall_config::UdpMatches {
    fn from(from: UdpMatches) -> Self {
        Self {
            src_port: from.src_port.map(std::convert::Into::into),
            dst_port: from.dst_port.map(std::convert::Into::into),
            length: from.length,
        }
    }
}

impl From<IcmpMatches> for namib_shared::firewall_config::IcmpMatches {
    fn from(from: IcmpMatches) -> Self {
        Self {
            icmp_type: from.icmp_type,
            icmp_code: from.icmp_code,
            rest_of_header: from.rest_of_header,
        }
    }
}

impl From<TcpOptions> for namib_shared::firewall_config::TcpOptions {
    fn from(from: TcpOptions) -> Self {
        Self {
            kind: from.kind,
            length: from.length,
            data: from.data,
        }
    }
}

impl From<TcpHeaderFlags> for namib_shared::firewall_config::TcpHeaderFlags {
    fn from(val: TcpHeaderFlags) -> Self {
        namib_shared::firewall_config::TcpHeaderFlags {
            cwr: val.cwr,
            ece: val.ece,
            urg: val.urg,
            ack: val.ack,
            psh: val.psh,
            rst: val.rst,
            syn: val.syn,
            fin: val.fin,
        }
    }
}

impl From<L4Matches> for namib_shared::firewall_config::L4Matches {
    fn from(from: L4Matches) -> Self {
        match from {
            L4Matches::Tcp(matches) => Self::Tcp(matches.into()),
            L4Matches::Udp(matches) => Self::Udp(matches.into()),
            L4Matches::Icmp(matches) => Self::Icmp(matches.into()),
        }
    }
}

/// Convert the L3 matches info from MUD data into the additional L3 matching data for the
/// firewall, IFF at least one of the additional fields is specified.
fn convert_l3_matches_info(from: &Option<L3Matches>) -> Option<namib_shared::firewall_config::L3MatchesExtra> {
    match from {
        None => None,
        Some(l3_matches) => match l3_matches {
            L3Matches::Ipv4(ipv4_matches) => {
                if ipv4_matches.dscp.is_none()
                    && ipv4_matches.ecn.is_none()
                    && ipv4_matches.length.is_none()
                    && ipv4_matches.ttl.is_none()
                    && ipv4_matches.ihl.is_none()
                    && ipv4_matches.flags.is_none()
                    && ipv4_matches.offset.is_none()
                    && ipv4_matches.identification.is_none()
                {
                    None
                } else {
                    Some(namib_shared::firewall_config::L3MatchesExtra::Ipv4(
                        namib_shared::firewall_config::Ipv4MatchesExtra {
                            dscp: ipv4_matches.dscp,
                            ecn: ipv4_matches.ecn,
                            length: ipv4_matches.length,
                            ttl: ipv4_matches.ttl,
                            ihl: ipv4_matches.ihl,
                            flags: ipv4_matches.flags.clone().map(std::convert::Into::into),
                            offset: ipv4_matches.offset,
                            identification: ipv4_matches.identification,
                        },
                    ))
                }
            },
            L3Matches::Ipv6(ipv6_matches) => {
                if ipv6_matches.dscp.is_none()
                    && ipv6_matches.ecn.is_none()
                    && ipv6_matches.length.is_none()
                    && ipv6_matches.ttl.is_none()
                    && ipv6_matches.flow_label.is_none()
                {
                    None
                } else {
                    Some(namib_shared::firewall_config::L3MatchesExtra::Ipv6(
                        namib_shared::firewall_config::Ipv6MatchesExtra {
                            dscp: ipv6_matches.dscp,
                            ecn: ipv6_matches.ecn,
                            length: ipv6_matches.length,
                            ttl: ipv6_matches.ttl,
                            flow_label: ipv6_matches.flow_label,
                        },
                    ))
                }
            },
        },
    }
}

impl From<Ipv4HeaderFlags> for namib_shared::firewall_config::Ipv4HeaderFlags {
    fn from(from: Ipv4HeaderFlags) -> Self {
        Self {
            reserved: from.reserved,
            fragment: from.fragment,
            more: from.more,
        }
    }
}

/// Returns the source and destination ordered as "this" and the "other" device, based on the
/// given `AclDirection`.
fn ordered_by_direction<T>(src: T, dst: T, direction: AclDirection) -> (T, T) {
    match direction {
        AclDirection::FromDevice => (src, dst),
        AclDirection::ToDevice => (dst, src),
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use namib_shared::macaddr::MacAddr;
    use regex::Regex;

    use super::*;
    use crate::models::{
        Ace, AceAction, AceMatches, AceProtocol, Acl, AclDirection, AclType, Device, IcmpMatches, Ipv4Matches,
        L3Matches, L4Matches, MudData, MudMatches, QuarantineException, TcpMatches,
    };

    #[test]
    fn test_acl_merging() {
        let original_acls = vec![
            Acl {
                name: "acl_to_device".to_string(),
                packet_direction: AclDirection::ToDevice,
                acl_type: AclType::IPV6,
                ace: vec![Ace {
                    name: "acl_to_device_0".to_string(),
                    action: AceAction::Accept,
                    matches: AceMatches {
                        l3: Some(L3Matches::Ipv4(Ipv4Matches {
                            protocol: Some(AceProtocol::Tcp),
                            src_network: None,
                            dst_network: None,
                            src_dnsname: None,
                            dst_dnsname: None,
                            dscp: None,
                            ecn: None,
                            length: None,
                            ttl: None,
                            ihl: None,
                            flags: None,
                            offset: None,
                            identification: None,
                        })),
                        l4: None,
                        mud: None,
                    },
                }],
            },
            Acl {
                name: "acl_from_device".to_string(),
                packet_direction: AclDirection::FromDevice,
                acl_type: AclType::IPV4,
                ace: vec![Ace {
                    name: "acl_from_device_0".to_string(),
                    action: AceAction::Deny,
                    matches: AceMatches {
                        l3: Some(L3Matches::Ipv4(Ipv4Matches {
                            protocol: Some(AceProtocol::Tcp),
                            src_network: None,
                            dst_network: None,
                            src_dnsname: None,
                            dst_dnsname: None,
                            dscp: None,
                            ecn: None,
                            length: None,
                            ttl: None,
                            ihl: None,
                            flags: None,
                            offset: None,
                            identification: None,
                        })),
                        l4: None,
                        mud: None,
                    },
                }],
            },
        ];

        let override_acls = vec![
            Acl {
                name: "acl_to_device".to_string(),
                packet_direction: AclDirection::ToDevice,
                acl_type: AclType::IPV4,
                ace: vec![Ace {
                    name: "acl_to_device_0".to_string(),
                    action: AceAction::Accept,
                    matches: AceMatches {
                        l3: Some(L3Matches::Ipv4(Ipv4Matches {
                            protocol: Some(AceProtocol::Tcp),
                            src_network: None,
                            dst_network: None,
                            src_dnsname: None,
                            dst_dnsname: None,
                            dscp: None,
                            ecn: None,
                            length: None,
                            ttl: None,
                            ihl: None,
                            flags: None,
                            offset: None,
                            identification: None,
                        })),
                        l4: None,
                        mud: None,
                    },
                }],
            },
            Acl {
                name: "acl_around_device_or_sth".to_string(),
                packet_direction: AclDirection::FromDevice,
                acl_type: AclType::IPV4,
                ace: vec![Ace {
                    name: "acl_around_device_or_sth_0".to_string(),
                    action: AceAction::Accept,
                    matches: AceMatches {
                        l3: Some(L3Matches::Ipv4(Ipv4Matches {
                            protocol: Some(AceProtocol::Udp),
                            src_network: None,
                            dst_network: None,
                            src_dnsname: None,
                            dst_dnsname: None,
                            dscp: None,
                            ecn: None,
                            length: None,
                            ttl: None,
                            ihl: None,
                            flags: None,
                            offset: None,
                            identification: None,
                        })),
                        l4: None,
                        mud: None,
                    },
                }],
            },
        ];

        let merged_acls = merge_acls(&original_acls, &override_acls);

        let to_device_acl = merged_acls
            .iter()
            .find(|acl| acl.name == "acl_to_device")
            .expect("acl_to_device not in acls");
        assert_eq!(to_device_acl.ace, override_acls[0].ace);
        assert_eq!(to_device_acl.acl_type, override_acls[0].acl_type);
        assert_eq!(to_device_acl.packet_direction, override_acls[0].packet_direction);

        let from_device_acl = merged_acls
            .iter()
            .find(|acl| acl.name == "acl_from_device")
            .expect("acl_from_device not in acls");
        assert_eq!(from_device_acl.ace, original_acls[1].ace);
        assert_eq!(from_device_acl.acl_type, original_acls[1].acl_type);
        assert_eq!(from_device_acl.packet_direction, original_acls[1].packet_direction);

        let around_device_or_sth_acl = merged_acls
            .iter()
            .find(|acl| acl.name == "acl_around_device_or_sth")
            .expect("acl_around_device_or_sth not in acls");
        assert_eq!(around_device_or_sth_acl.ace, override_acls[1].ace);
        assert_eq!(around_device_or_sth_acl.acl_type, override_acls[1].acl_type);
        assert_eq!(
            around_device_or_sth_acl.packet_direction,
            override_acls[1].packet_direction
        );
    }

    #[test]
    fn test_overridden_acls_to_firewall_rules() {
        let mud_data = MudData {
            url: "https://example.com/.well-known/mud".to_string(),
            masa_url: None,
            last_update: "some_last_update".to_string(),
            systeminfo: Some("some_systeminfo".to_string()),
            mfg_name: Some("some_mfg_name".to_string()),
            model_name: Some("some_model_name".to_string()),
            documentation: Some("some_documentation".to_string()),
            expiration: Utc::now(),
            acllist: vec![Acl {
                name: "some_acl_name".to_string(),
                packet_direction: AclDirection::ToDevice,
                acl_type: AclType::IPV6,
                ace: vec![Ace {
                    name: "some_ace_name".to_string(),
                    action: AceAction::Accept,
                    matches: AceMatches {
                        l3: Some(L3Matches::Ipv4(Ipv4Matches {
                            protocol: Some(AceProtocol::Tcp),
                            src_network: None,
                            dst_network: None,
                            src_dnsname: Some(String::from("www.example.test")),
                            dst_dnsname: None,
                            dscp: None,
                            ecn: None,
                            length: None,
                            ttl: None,
                            ihl: None,
                            flags: None,
                            offset: None,
                            identification: None,
                        })),
                        l4: None,
                        mud: None,
                    },
                }],
            }],
            acl_override: vec![Acl {
                name: "some_acl_name".to_string(),
                packet_direction: AclDirection::ToDevice,
                acl_type: AclType::IPV4,
                ace: vec![Ace {
                    name: "overriden_ace".to_string(),
                    action: AceAction::Deny,
                    matches: AceMatches {
                        l3: Some(L3Matches::Ipv4(Ipv4Matches {
                            protocol: Some(AceProtocol::Udp),
                            src_network: None,
                            dst_network: None,
                            src_dnsname: Some(String::from("www.example.test")),
                            dst_dnsname: None,
                            dscp: None,
                            ecn: None,
                            length: None,
                            ttl: None,
                            ihl: None,
                            flags: None,
                            offset: None,
                            identification: None,
                        })),
                        l4: None,
                        mud: None,
                    },
                }],
            }],
        };

        let device = DeviceWithRefs {
            inner: Device {
                id: 0,
                name: None,
                mac_addr: Some("aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap().into()),
                duid: None,
                ipv4_addr: "127.0.0.1".parse().ok(),
                ipv6_addr: None,
                hostname: "".to_string(),
                vendor_class: "".to_string(),
                mud_url: Some("https://example.com/mud_url.json".to_string()),
                last_interaction: Utc::now().naive_utc(),
                collect_info: false,
                fa_icon: None,
                room_id: None,
                q_bit: false,
            },
            mud_data: Some(mud_data),
            room: None,
            controller_mappings: vec![],
            quarantine_exceptions: vec![],
            flow_scopes: vec![],
        };

        let admin_context = AdministrativeContext {
            dns_mappings: vec![
                DefinedServer::Url("https://me.org/mud-devices/my-dns-server.json".to_string()),
                DefinedServer::Ip("192.168.0.1".parse().unwrap()),
            ],
            ntp_mappings: vec![DefinedServer::Ip("123.45.67.89".parse().unwrap())],
        };

        let x = convert_device_to_fw_rules(&device, &[device.clone()], &admin_context);

        let resulting_device = FirewallDevice {
            id: device.id,
            ipv4_addr: device.ipv4_addr,
            ipv6_addr: device.ipv6_addr,
            rules: vec![
                FirewallRule::new(
                    String::from("rule_0"),
                    Some(RuleTargetHost::Hostname(String::from("www.example.test"))),
                    Some(RuleTargetHost::FirewallDevice),
                    None,
                    Some(namib_shared::firewall_config::L4Matches::Udp(
                        namib_shared::firewall_config::UdpMatches::default(),
                    )),
                    Verdict::Reject,
                    ScopeConstraint::None,
                ),
                FirewallRule::new(
                    String::from("rule_dns_default_accept_1"),
                    Some(RuleTargetHost::FirewallDevice),
                    Some(RuleTargetHost::Hostname(String::from(
                        "https://me.org/mud-devices/my-dns-server.json",
                    ))),
                    None,
                    Some(namib_shared::firewall_config::L4Matches::Tcp(
                        namib_shared::firewall_config::TcpMatches::only_ports(None, Some(PortOrRange::Single(53))),
                    )),
                    Verdict::Accept,
                    ScopeConstraint::None,
                ),
                FirewallRule::new(
                    String::from("rule_dns_default_accept_2"),
                    Some(RuleTargetHost::FirewallDevice),
                    Some(RuleTargetHost::Hostname(String::from(
                        "https://me.org/mud-devices/my-dns-server.json",
                    ))),
                    None,
                    Some(namib_shared::firewall_config::L4Matches::Udp(
                        namib_shared::firewall_config::UdpMatches::only_ports(None, Some(PortOrRange::Single(53))),
                    )),
                    Verdict::Accept,
                    ScopeConstraint::None,
                ),
                FirewallRule::new(
                    String::from("rule_dns_default_accept_3"),
                    Some(RuleTargetHost::FirewallDevice),
                    Some(RuleTargetHost::Ip("192.168.0.1".parse().unwrap())),
                    None,
                    Some(namib_shared::firewall_config::L4Matches::Tcp(
                        namib_shared::firewall_config::TcpMatches::only_ports(None, Some(PortOrRange::Single(53))),
                    )),
                    Verdict::Accept,
                    ScopeConstraint::None,
                ),
                FirewallRule::new(
                    String::from("rule_dns_default_accept_4"),
                    Some(RuleTargetHost::FirewallDevice),
                    Some(RuleTargetHost::Ip("192.168.0.1".parse().unwrap())),
                    None,
                    Some(namib_shared::firewall_config::L4Matches::Udp(
                        namib_shared::firewall_config::UdpMatches::only_ports(None, Some(PortOrRange::Single(53))),
                    )),
                    Verdict::Accept,
                    ScopeConstraint::None,
                ),
                FirewallRule::new(
                    String::from("rule_ntp_default_accept_5"),
                    Some(RuleTargetHost::FirewallDevice),
                    Some(RuleTargetHost::Ip("123.45.67.89".parse().unwrap())),
                    None,
                    Some(namib_shared::firewall_config::L4Matches::Tcp(
                        namib_shared::firewall_config::TcpMatches::only_ports(None, Some(PortOrRange::Single(123))),
                    )),
                    Verdict::Accept,
                    ScopeConstraint::None,
                ),
                FirewallRule::new(
                    String::from("rule_ntp_default_accept_6"),
                    Some(RuleTargetHost::FirewallDevice),
                    Some(RuleTargetHost::Ip("123.45.67.89".parse().unwrap())),
                    None,
                    Some(namib_shared::firewall_config::L4Matches::Udp(
                        namib_shared::firewall_config::UdpMatches::only_ports(None, Some(PortOrRange::Single(123))),
                    )),
                    Verdict::Accept,
                    ScopeConstraint::None,
                ),
                FirewallRule::new(
                    String::from("rule_default_7"),
                    Some(RuleTargetHost::FirewallDevice),
                    None,
                    None,
                    None,
                    Verdict::Reject,
                    ScopeConstraint::None,
                ),
                FirewallRule::new(
                    String::from("rule_default_8"),
                    None,
                    Some(RuleTargetHost::FirewallDevice),
                    None,
                    None,
                    Verdict::Reject,
                    ScopeConstraint::None,
                ),
            ],
            collect_data: false,
        };

        assert_eq!(x, resulting_device);
    }

    #[test]
    fn test_converting() {
        let mud_data = MudData {
            url: "https://example.com/.well-known/mud".to_string(),
            masa_url: None,
            last_update: "some_last_update".to_string(),
            systeminfo: Some("some_systeminfo".to_string()),
            mfg_name: Some("some_mfg_name".to_string()),
            model_name: Some("some_model_name".to_string()),
            documentation: Some("some_documentation".to_string()),
            expiration: Utc::now(),
            acllist: vec![
                Acl {
                    name: "some_acl_name".to_string(),
                    packet_direction: AclDirection::ToDevice,
                    acl_type: AclType::IPV6,
                    ace: vec![Ace {
                        name: "some_ace_name".to_string(),
                        action: AceAction::Accept,
                        matches: AceMatches {
                            l3: Some(L3Matches::Ipv4(Ipv4Matches {
                                protocol: Some(AceProtocol::Tcp),
                                src_network: None,
                                dst_network: None,
                                src_dnsname: Some(String::from("www.example.test")),
                                dst_dnsname: None,
                                dscp: None,
                                ecn: None,
                                length: None,
                                ttl: None,
                                ihl: None,
                                flags: None,
                                offset: None,
                                identification: None,
                            })),
                            l4: Some(L4Matches::Tcp(TcpMatches {
                                direction_initiated: None,
                                src_port: Some(AcePort::Single(123)),
                                dst_port: Some(AcePort::Range(50, 60)),
                                sequence_number: None,
                                acknowledgement_number: None,
                                data_offset: None,
                                reserved: None,
                                flags: None,
                                window_size: None,
                                urgent_pointer: None,
                                options: None,
                            })),
                            mud: None,
                        },
                    }],
                },
                Acl {
                    name: "other_acl_name".to_string(),
                    packet_direction: AclDirection::FromDevice,
                    acl_type: AclType::IPV6,
                    ace: vec![Ace {
                        name: "other_ace_name".to_string(),
                        action: AceAction::Accept,
                        matches: AceMatches {
                            l3: Some(L3Matches::Ipv4(Ipv4Matches {
                                protocol: Some(AceProtocol::Udp),
                                src_network: None,
                                dst_network: None,
                                src_dnsname: None,
                                dst_dnsname: Some(String::from("www.example.test")),
                                dscp: None,
                                ecn: None,
                                length: None,
                                ttl: None,
                                ihl: None,
                                flags: None,
                                offset: None,
                                identification: None,
                            })),
                            l4: Some(L4Matches::Udp(UdpMatches {
                                src_port: Some(AcePort::Range(8000, 8080)),
                                dst_port: Some(AcePort::Single(56)),
                                length: None,
                            })),
                            mud: None,
                        },
                    }],
                },
            ],
            acl_override: Vec::default(),
        };

        let device = DeviceWithRefs {
            inner: Device {
                id: 0,
                name: None,
                mac_addr: Some("aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap().into()),
                duid: None,
                ipv4_addr: "127.0.0.1".parse().ok(),
                ipv6_addr: None,
                hostname: "".to_string(),
                vendor_class: "".to_string(),
                mud_url: Some("https://example.com/mud_url.json".to_string()),
                collect_info: true,
                last_interaction: Utc::now().naive_utc(),
                fa_icon: None,
                room_id: None,
                q_bit: false,
            },
            mud_data: Some(mud_data),
            room: None,
            controller_mappings: vec![],
            quarantine_exceptions: vec![],
            flow_scopes: vec![],
        };

        let actual = convert_device_to_fw_rules(&device, &[device.clone()], &AdministrativeContext::default());

        let expected = FirewallDevice {
            id: device.id,
            ipv4_addr: device.ipv4_addr,
            ipv6_addr: device.ipv6_addr,
            rules: vec![
                FirewallRule::new(
                    String::from("rule_0"),
                    Some(RuleTargetHost::Hostname(String::from("www.example.test"))),
                    Some(RuleTargetHost::FirewallDevice),
                    None,
                    Some(namib_shared::firewall_config::L4Matches::Tcp(
                        namib_shared::firewall_config::TcpMatches::only_ports(
                            Some(PortOrRange::Single(123)),
                            Some(PortOrRange::Range(50, 60)),
                        ),
                    )),
                    Verdict::Accept,
                    ScopeConstraint::None,
                ),
                FirewallRule::new(
                    String::from("rule_1"),
                    Some(RuleTargetHost::FirewallDevice),
                    Some(RuleTargetHost::Hostname(String::from("www.example.test"))),
                    None,
                    Some(namib_shared::firewall_config::L4Matches::Udp(
                        namib_shared::firewall_config::UdpMatches::only_ports(
                            Some(PortOrRange::Range(8000, 8080)),
                            Some(PortOrRange::Single(56)),
                        ),
                    )),
                    Verdict::Accept,
                    ScopeConstraint::None,
                ),
                FirewallRule::new(
                    String::from("rule_default_2"),
                    Some(RuleTargetHost::FirewallDevice),
                    None,
                    None,
                    None,
                    Verdict::Reject,
                    ScopeConstraint::None,
                ),
                FirewallRule::new(
                    String::from("rule_default_3"),
                    None,
                    Some(RuleTargetHost::FirewallDevice),
                    None,
                    None,
                    Verdict::Reject,
                    ScopeConstraint::None,
                ),
            ],
            collect_data: true,
        };

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_my_controller() {
        // create bulb
        let bulb_mud_data = MudData {
            url: "https://manufacturer.com/devices/bulb".to_string(),
            masa_url: None,
            last_update: "some_last_update".to_string(),
            systeminfo: Some("some_systeminfo".to_string()),
            mfg_name: Some("some_mfg_name".to_string()),
            model_name: Some("some_model_name".to_string()),
            documentation: Some("some_documentation".to_string()),
            expiration: Utc::now(),
            acllist: vec![Acl {
                name: "some_acl_name".to_string(),
                packet_direction: AclDirection::FromDevice,
                acl_type: AclType::IPV4,
                ace: vec![Ace {
                    name: "some_ace_name".to_string(),
                    action: AceAction::Accept,
                    matches: AceMatches {
                        l3: Some(L3Matches::Ipv4(Ipv4Matches {
                            protocol: Some(AceProtocol::Tcp),
                            src_network: None,
                            dst_network: None,
                            src_dnsname: None,
                            dst_dnsname: None,
                            dscp: None,
                            ecn: None,
                            length: None,
                            ttl: None,
                            ihl: None,
                            flags: None,
                            offset: None,
                            identification: None,
                        })),
                        l4: None,
                        mud: Some(MudMatches {
                            manufacturer: None,
                            same_manufacturer: false,
                            controller: None,
                            my_controller: true,
                            local: false,
                            model: None,
                        }),
                    },
                }],
            }],
            acl_override: Vec::default(),
        };
        let bulb = DeviceWithRefs {
            inner: Device {
                id: 0,
                name: None,
                mac_addr: Some("aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap().into()),
                duid: None,
                ipv4_addr: "10.0.0.3".parse().ok(),
                ipv6_addr: None,
                hostname: "".to_string(),
                vendor_class: "".to_string(),
                mud_url: Some("https://manufacturer.com/devices/bulb".to_string()),
                collect_info: true,
                last_interaction: Utc::now().naive_utc(),
                fa_icon: None,
                room_id: None,
                q_bit: false,
            },
            mud_data: Some(bulb_mud_data),
            room: None,
            controller_mappings: vec![ConfiguredControllerMapping::Uri(
                "https://manufacturer.com/devices/bridge".to_string(),
            )],
            quarantine_exceptions: vec![],
            flow_scopes: vec![],
        };

        // create bridge
        let bridge_mud_data = MudData {
            url: "https://manufacturer.com/devices/bridge".to_string(),
            masa_url: None,
            last_update: "some_last_update".to_string(),
            systeminfo: Some("some_systeminfo".to_string()),
            mfg_name: Some("some_mfg_name".to_string()),
            model_name: Some("some_model_name".to_string()),
            documentation: Some("some_documentation".to_string()),
            expiration: Utc::now(),
            acllist: vec![Acl {
                name: "some_acl_name".to_string(),
                packet_direction: AclDirection::FromDevice,
                acl_type: AclType::IPV4,
                ace: Vec::default(),
            }],
            acl_override: Vec::default(),
        };
        let bridge = DeviceWithRefs {
            inner: Device {
                id: 0,
                name: None,
                mac_addr: Some("ff:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap().into()),
                duid: None,
                ipv4_addr: "10.0.0.2".parse().ok(),
                ipv6_addr: None,
                hostname: "".to_string(),
                vendor_class: "".to_string(),
                mud_url: Some("https://manufacturer.com/devices/bridge".to_string()),
                collect_info: true,
                last_interaction: Utc::now().naive_utc(),
                fa_icon: None,
                room_id: None,
                q_bit: false,
            },
            mud_data: Some(bridge_mud_data),
            room: None,
            controller_mappings: vec![],
            quarantine_exceptions: vec![],
            flow_scopes: vec![],
        };

        let bulb_firewall_rules_result = convert_device_to_fw_rules(
            &bulb,
            &[bulb.clone(), bridge.clone()],
            &AdministrativeContext::default(),
        );

        let rule_result: Vec<&FirewallRule> = bulb_firewall_rules_result
            .rules
            .iter()
            .filter(|&r| {
                r.src.as_ref() == Some(&RuleTargetHost::FirewallDevice)
                    && r.dst.as_ref() == Some(&RuleTargetHost::Ip(bridge.ipv4_addr.unwrap().into()))
            })
            .collect();

        assert!(rule_result.len() == 1);

        let rule = rule_result[0];
        assert_eq!(rule.verdict, Verdict::Accept);
    }

    #[test]
    fn test_controller() {
        // create bulb
        let bulb_mud_data = MudData {
            url: "https://manufacturer.com/devices/bulb".to_string(),
            masa_url: None,
            last_update: "some_last_update".to_string(),
            systeminfo: Some("some_systeminfo".to_string()),
            mfg_name: Some("some_mfg_name".to_string()),
            model_name: Some("some_model_name".to_string()),
            documentation: Some("some_documentation".to_string()),
            expiration: Utc::now(),
            acllist: vec![Acl {
                name: "some_acl_name".to_string(),
                packet_direction: AclDirection::FromDevice,
                acl_type: AclType::IPV4,
                ace: vec![Ace {
                    name: "some_ace_name".to_string(),
                    action: AceAction::Accept,
                    matches: AceMatches {
                        l3: Some(L3Matches::Ipv4(Ipv4Matches {
                            protocol: Some(AceProtocol::Tcp),
                            src_network: None,
                            dst_network: None,
                            src_dnsname: None,
                            dst_dnsname: None,
                            dscp: None,
                            ecn: None,
                            length: None,
                            ttl: None,
                            ihl: None,
                            flags: None,
                            offset: None,
                            identification: None,
                        })),
                        l4: None,
                        mud: Some(MudMatches {
                            manufacturer: None,
                            same_manufacturer: false,
                            controller: Some("https://manufacturer.com/devices/bridge".to_string()),
                            my_controller: false,
                            local: false,
                            model: None,
                        }),
                    },
                }],
            }],
            acl_override: Vec::default(),
        };
        let bulb = DeviceWithRefs {
            inner: Device {
                id: 0,
                name: None,
                mac_addr: Some("aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap().into()),
                duid: None,
                ipv4_addr: "10.0.0.3".parse().ok(),
                ipv6_addr: None,
                hostname: "".to_string(),
                vendor_class: "".to_string(),
                mud_url: Some("https://manufacturer.com/devices/bulb".to_string()),
                collect_info: true,
                last_interaction: Utc::now().naive_utc(),
                fa_icon: None,
                room_id: None,
                q_bit: false,
            },
            mud_data: Some(bulb_mud_data),
            room: None,
            controller_mappings: vec![],
            quarantine_exceptions: vec![],
            flow_scopes: vec![],
        };

        // create bridge
        let bridge_mud_data = MudData {
            url: "https://manufacturer.com/devices/bridge".to_string(),
            masa_url: None,
            last_update: "some_last_update".to_string(),
            systeminfo: Some("some_systeminfo".to_string()),
            mfg_name: Some("some_mfg_name".to_string()),
            model_name: Some("some_model_name".to_string()),
            documentation: Some("some_documentation".to_string()),
            expiration: Utc::now(),
            acllist: vec![Acl {
                name: "some_acl_name".to_string(),
                packet_direction: AclDirection::FromDevice,
                acl_type: AclType::IPV4,
                ace: Vec::default(),
            }],
            acl_override: Vec::default(),
        };
        let bridge = DeviceWithRefs {
            inner: Device {
                id: 0,
                name: None,
                mac_addr: Some("ff:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap().into()),
                duid: None,
                ipv4_addr: "10.0.0.2".parse().ok(),
                ipv6_addr: None,
                hostname: "".to_string(),
                vendor_class: "".to_string(),
                mud_url: Some("https://manufacturer.com/devices/bridge".to_string()),
                collect_info: true,
                last_interaction: Utc::now().naive_utc(),
                fa_icon: None,
                room_id: None,
                q_bit: false,
            },
            mud_data: Some(bridge_mud_data),
            room: None,
            controller_mappings: vec![],
            quarantine_exceptions: vec![],
            flow_scopes: vec![],
        };

        let bulb_firewall_rules_result = convert_device_to_fw_rules(
            &bulb,
            &[bulb.clone(), bridge.clone()],
            &AdministrativeContext::default(),
        );

        let rule_result: Vec<&FirewallRule> = bulb_firewall_rules_result
            .rules
            .iter()
            .filter(|&r| {
                r.src.as_ref() == Some(&RuleTargetHost::FirewallDevice)
                    && r.dst.as_ref() == Some(&RuleTargetHost::Ip(bridge.ipv4_addr.unwrap().into()))
            })
            .collect();

        assert!(rule_result.len() == 1);

        let rule = rule_result[0];
        assert_eq!(rule.verdict, Verdict::Accept);
    }

    #[test]
    fn test_same_manufacturer() {
        let mud_data = MudData {
            url: "https://example.com/.well-known/mud".to_string(),
            masa_url: None,
            last_update: "some_last_update".to_string(),
            systeminfo: Some("some_systeminfo".to_string()),
            mfg_name: Some("some_mfg_name".to_string()),
            model_name: Some("some_model_name".to_string()),
            documentation: Some("some_documentation".to_string()),
            expiration: Utc::now(),
            acllist: vec![Acl {
                name: "some_acl_name".to_string(),
                packet_direction: AclDirection::FromDevice,
                acl_type: AclType::IPV4,
                ace: vec![Ace {
                    name: "some_ace_name".to_string(),
                    action: AceAction::Accept,
                    matches: AceMatches {
                        l3: Some(L3Matches::Ipv4(Ipv4Matches {
                            protocol: Some(AceProtocol::Tcp),
                            src_network: None,
                            dst_network: None,
                            src_dnsname: None,
                            dst_dnsname: None,
                            dscp: None,
                            ecn: None,
                            length: None,
                            ttl: None,
                            ihl: None,
                            flags: None,
                            offset: None,
                            identification: None,
                        })),
                        l4: Some(L4Matches::Tcp(TcpMatches {
                            sequence_number: None,
                            acknowledgement_number: None,
                            data_offset: None,
                            reserved: None,
                            flags: None,
                            window_size: None,
                            urgent_pointer: None,
                            options: None,
                            direction_initiated: None,
                            src_port: Some(AcePort::Single(321)),
                            dst_port: Some(AcePort::Single(500)),
                        })),
                        mud: Some(MudMatches {
                            manufacturer: None,
                            same_manufacturer: true,
                            controller: None,
                            my_controller: false,
                            local: false,
                            model: None,
                        }),
                    },
                }],
            }],
            acl_override: Vec::default(),
        };

        let device = DeviceWithRefs {
            inner: Device {
                id: 0,
                name: None,
                mac_addr: Some("aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap().into()),
                duid: None,
                ipv4_addr: "127.0.0.1".parse().ok(),
                ipv6_addr: None,
                hostname: "".to_string(),
                vendor_class: "".to_string(),
                mud_url: Some("https://example.com/mud_url.json".to_string()),
                collect_info: true,
                last_interaction: Utc::now().naive_utc(),
                fa_icon: None,
                room_id: None,
                q_bit: false,
            },
            mud_data: Some(mud_data),
            room: None,
            controller_mappings: vec![],
            quarantine_exceptions: vec![],
            flow_scopes: vec![],
        };

        let mud_data1 = MudData {
            url: "https://example.com/.well-known/mud".to_string(),
            masa_url: None,
            last_update: "some_last_update".to_string(),
            systeminfo: Some("some_systeminfo".to_string()),
            mfg_name: Some("some_mfg_name".to_string()),
            model_name: Some("some_model_name".to_string()),
            documentation: Some("some_documentation".to_string()),
            expiration: Utc::now(),
            acllist: vec![Acl {
                name: "some_acl_name".to_string(),
                packet_direction: AclDirection::ToDevice,
                acl_type: AclType::IPV4,
                ace: vec![Ace {
                    name: "some_ace_name".to_string(),
                    action: AceAction::Accept,
                    matches: AceMatches {
                        l3: Some(L3Matches::Ipv4(Ipv4Matches {
                            protocol: Some(AceProtocol::Tcp),
                            src_network: None,
                            dst_network: None,
                            src_dnsname: None,
                            dst_dnsname: None,
                            dscp: None,
                            ecn: None,
                            length: None,
                            ttl: None,
                            ihl: None,
                            flags: None,
                            offset: None,
                            identification: None,
                        })),
                        l4: None,
                        mud: None,
                    },
                }],
            }],
            acl_override: Vec::default(),
        };

        let device1 = DeviceWithRefs {
            inner: Device {
                id: 1,
                name: None,
                mac_addr: Some("aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap().into()),
                duid: None,
                ipv4_addr: "127.0.0.2".parse().ok(),
                ipv6_addr: None,
                hostname: "".to_string(),
                vendor_class: "".to_string(),
                mud_url: Some("https://example.com/mud_url.json".to_string()),
                collect_info: true,
                last_interaction: Utc::now().naive_utc(),
                fa_icon: None,
                room_id: None,
                q_bit: false,
            },
            mud_data: Some(mud_data1),
            room: None,
            controller_mappings: vec![],
            quarantine_exceptions: vec![],
            flow_scopes: vec![],
        };

        let resulting_device = FirewallDevice {
            id: device.id,
            ipv4_addr: device.ipv4_addr,
            ipv6_addr: device.ipv6_addr,
            rules: vec![
                FirewallRule::new(
                    String::from("rule_0"),
                    Some(RuleTargetHost::FirewallDevice),
                    Some(RuleTargetHost::Ip(IpAddr::V4(device1.ipv4_addr.unwrap()))),
                    None,
                    Some(namib_shared::firewall_config::L4Matches::Tcp(
                        namib_shared::firewall_config::TcpMatches::only_ports(
                            Some(PortOrRange::Single(321)),
                            Some(PortOrRange::Single(500)),
                        ),
                    )),
                    Verdict::Accept,
                    ScopeConstraint::None,
                ),
                FirewallRule::new(
                    String::from("rule_default_1"),
                    Some(RuleTargetHost::FirewallDevice),
                    None,
                    None,
                    None,
                    Verdict::Reject,
                    ScopeConstraint::None,
                ),
                FirewallRule::new(
                    String::from("rule_default_2"),
                    None,
                    Some(RuleTargetHost::FirewallDevice),
                    None,
                    None,
                    Verdict::Reject,
                    ScopeConstraint::None,
                ),
            ],
            collect_data: true,
        };

        let x = convert_device_to_fw_rules(&device, &[device.clone(), device1], &AdministrativeContext::default());

        assert_eq!(x, resulting_device);
    }

    #[test]
    fn test_model_matching() {
        let mud_data = MudData {
            url: "https://simple-example.com/.well-known/mud".to_string(),
            masa_url: None,
            last_update: "some_last_update".to_string(),
            systeminfo: Some("some_systeminfo".to_string()),
            mfg_name: Some("some_mfg_name".to_string()),
            model_name: Some("some_model_name".to_string()),
            documentation: Some("some_documentation".to_string()),
            expiration: Utc::now(),

            acllist: vec![Acl {
                name: "some_acl_name".to_string(),
                packet_direction: AclDirection::FromDevice,
                acl_type: AclType::IPV4,
                ace: vec![Ace {
                    name: "some_ace_name".to_string(),
                    action: AceAction::Accept,
                    matches: AceMatches {
                        l3: Some(L3Matches::Ipv4(Ipv4Matches {
                            protocol: Some(AceProtocol::Tcp),
                            src_network: None,
                            dst_network: None,
                            src_dnsname: None,
                            dst_dnsname: None,
                            dscp: None,
                            ecn: None,
                            length: None,
                            ttl: None,
                            ihl: None,
                            flags: None,
                            offset: None,
                            identification: None,
                        })),
                        l4: Some(L4Matches::Tcp(TcpMatches {
                            sequence_number: None,
                            acknowledgement_number: None,
                            data_offset: None,
                            reserved: None,
                            flags: None,
                            window_size: None,
                            urgent_pointer: None,
                            options: None,
                            direction_initiated: None,
                            src_port: Some(AcePort::Single(123)),
                            dst_port: Some(AcePort::Range(50, 60)),
                        })),
                        mud: Some(MudMatches {
                            manufacturer: None,
                            same_manufacturer: false,
                            controller: None,
                            my_controller: false,
                            local: false,
                            model: Some("https://example.com/.well-known/mud".to_string()),
                        }),
                    },
                }],
            }],
            acl_override: Vec::default(),
        };

        let device = DeviceWithRefs {
            inner: Device {
                id: 0,
                name: None,
                mac_addr: Some("aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap().into()),
                duid: None,
                ipv4_addr: "127.0.0.1".parse().ok(),
                ipv6_addr: None,
                hostname: "".to_string(),
                vendor_class: "".to_string(),
                mud_url: Some("https://simple-example.com/mud_url.json".to_string()),
                collect_info: true,
                last_interaction: Utc::now().naive_utc(),
                fa_icon: None,
                room_id: None,
                q_bit: false,
            },
            mud_data: Some(mud_data),
            room: None,
            controller_mappings: vec![],
            quarantine_exceptions: vec![],
            flow_scopes: vec![],
        };

        let mud_data1 = MudData {
            url: "https://example.com/.well-known/mud".to_string(),
            masa_url: None,
            last_update: "some_last_update".to_string(),
            systeminfo: Some("some_systeminfo".to_string()),
            mfg_name: Some("some_mfg_name".to_string()),
            model_name: Some("some_model_name".to_string()),
            documentation: Some("some_documentation".to_string()),
            expiration: Utc::now(),
            acllist: vec![],
            acl_override: Vec::default(),
        };

        let device1 = DeviceWithRefs {
            inner: Device {
                id: 1,
                name: None,
                mac_addr: Some("aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap().into()),
                duid: None,
                ipv4_addr: "127.0.0.2".parse().ok(),
                ipv6_addr: None,
                hostname: "".to_string(),
                vendor_class: "".to_string(),
                mud_url: Some("https://example.com/.well-known/mud".to_string()),
                collect_info: true,
                last_interaction: Utc::now().naive_utc(),
                fa_icon: None,
                room_id: None,
                q_bit: false,
            },
            mud_data: Some(mud_data1),
            room: None,
            controller_mappings: vec![],
            quarantine_exceptions: vec![],
            flow_scopes: vec![],
        };

        let x = convert_device_to_fw_rules(
            &device,
            &[device.clone(), device1.clone()],
            &AdministrativeContext::default(),
        );

        let resulting_device = FirewallDevice {
            id: device.id,
            ipv4_addr: device.ipv4_addr,
            ipv6_addr: device.ipv6_addr,
            rules: vec![
                FirewallRule::new(
                    String::from("rule_0"),
                    Some(RuleTargetHost::FirewallDevice),
                    Some(RuleTargetHost::Ip(IpAddr::V4(device1.inner.ipv4_addr.unwrap()))),
                    None,
                    Some(namib_shared::firewall_config::L4Matches::Tcp(
                        namib_shared::firewall_config::TcpMatches::only_ports(
                            Some(PortOrRange::Single(123)),
                            Some(PortOrRange::Range(50, 60)),
                        ),
                    )),
                    Verdict::Accept,
                    ScopeConstraint::None,
                ),
                FirewallRule::new(
                    String::from("rule_default_1"),
                    Some(RuleTargetHost::FirewallDevice),
                    None,
                    None,
                    None,
                    Verdict::Reject,
                    ScopeConstraint::None,
                ),
                FirewallRule::new(
                    String::from("rule_default_2"),
                    None,
                    Some(RuleTargetHost::FirewallDevice),
                    None,
                    None,
                    Verdict::Reject,
                    ScopeConstraint::None,
                ),
            ],
            collect_data: true,
        };
        assert_eq!(x, resulting_device);
    }

    #[test]
    fn test_local_networks() {
        // create bulb
        let bulb_mud_data = MudData {
            url: "https://manufacturer.com/devices/bulb".to_string(),
            masa_url: None,
            last_update: "some_last_update".to_string(),
            systeminfo: Some("some_systeminfo".to_string()),
            mfg_name: Some("some_mfg_name".to_string()),
            model_name: Some("some_model_name".to_string()),
            documentation: Some("some_documentation".to_string()),
            expiration: Utc::now(),
            acllist: vec![Acl {
                name: "some_acl_name".to_string(),
                packet_direction: AclDirection::FromDevice,
                acl_type: AclType::IPV4,
                ace: vec![Ace {
                    name: "some_ace_name".to_string(),
                    action: AceAction::Accept,
                    matches: AceMatches {
                        l3: Some(L3Matches::Ipv4(Ipv4Matches {
                            protocol: Some(AceProtocol::Tcp),
                            src_network: None,
                            dst_network: None,
                            src_dnsname: None,
                            dst_dnsname: None,
                            dscp: None,
                            ecn: None,
                            length: None,
                            ttl: None,
                            ihl: None,
                            flags: None,
                            offset: None,
                            identification: None,
                        })),
                        l4: None,
                        mud: Some(MudMatches {
                            manufacturer: None,
                            same_manufacturer: false,
                            controller: Some("https://manufacturer.com/devices/bridge".to_string()),
                            my_controller: false,
                            local: true, // the important definition for this test
                            model: None,
                        }),
                    },
                }],
            }],
            acl_override: Vec::default(),
        };
        let bulb = DeviceWithRefs {
            inner: Device {
                id: 0,
                name: None,
                mac_addr: Some("aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap().into()),
                duid: None,
                ipv4_addr: "123.45.6.78".parse().ok(),
                ipv6_addr: None,
                hostname: "".to_string(),
                vendor_class: "".to_string(),
                mud_url: Some("https://manufacturer.com/devices/bulb".to_string()),
                collect_info: true,
                last_interaction: Utc::now().naive_utc(),
                fa_icon: None,
                room_id: None,
                q_bit: false,
            },
            mud_data: Some(bulb_mud_data),
            room: None,
            controller_mappings: vec![],
            quarantine_exceptions: vec![],
            flow_scopes: vec![],
        };

        // create bridge
        let bridge_mud_data = MudData {
            url: "https://manufacturer.com/devices/bridge".to_string(),
            masa_url: None,
            last_update: "some_last_update".to_string(),
            systeminfo: Some("some_systeminfo".to_string()),
            mfg_name: Some("some_mfg_name".to_string()),
            model_name: Some("some_model_name".to_string()),
            documentation: Some("some_documentation".to_string()),
            expiration: Utc::now(),
            acllist: vec![Acl {
                name: "some_acl_name".to_string(),
                packet_direction: AclDirection::FromDevice,
                acl_type: AclType::IPV4,
                ace: Vec::default(),
            }],
            acl_override: Vec::default(),
        };
        let bridge = DeviceWithRefs {
            inner: Device {
                id: 0,
                name: None,
                mac_addr: Some("ff:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap().into()),
                duid: None,
                ipv4_addr: "123.45.67.8".parse().ok(),
                ipv6_addr: None,
                hostname: "".to_string(),
                vendor_class: "".to_string(),
                mud_url: Some("https://manufacturer.com/devices/bridge".to_string()),
                collect_info: true,
                last_interaction: Utc::now().naive_utc(),
                fa_icon: None,
                room_id: None,
                q_bit: false,
            },
            mud_data: Some(bridge_mud_data),
            room: None,
            controller_mappings: vec![],
            quarantine_exceptions: vec![],
            flow_scopes: vec![],
        };

        let bulb_firewall_rules_result = convert_device_to_fw_rules(
            &bulb,
            &[bulb.clone(), bridge.clone()],
            &AdministrativeContext::default(),
        );

        let controller_rule = bulb_firewall_rules_result
            .rules
            .iter()
            .find(|&r| {
                r.src.as_ref() == Some(&RuleTargetHost::FirewallDevice)
                    && r.dst.as_ref() == Some(&RuleTargetHost::Ip(bridge.ipv4_addr.unwrap().into()))
            })
            .expect("could not find firewall rule filtered for bridge target");
        assert_eq!(controller_rule.scope, ScopeConstraint::Local);

        let default_rule_regex = Regex::new(r"rule_default_\d+").unwrap();
        for default_rule in bulb_firewall_rules_result
            .rules
            .iter()
            .filter(|&r| default_rule_regex.is_match(&r.rule_name.to_string()))
        {
            assert_eq!(default_rule.scope, ScopeConstraint::None);
        }
    }

    #[test]
    fn test_manufacturer() {
        let mud_data = MudData {
            url: "https://example.com/.well-known/mud".to_string(),
            masa_url: None,
            last_update: "some_last_update".to_string(),
            systeminfo: Some("some_systeminfo".to_string()),
            mfg_name: Some("some_mfg_name".to_string()),
            model_name: Some("some_model_name".to_string()),
            documentation: Some("some_documentation".to_string()),
            expiration: Utc::now(),
            acllist: vec![Acl {
                name: "some_acl_name".to_string(),
                packet_direction: AclDirection::FromDevice,
                acl_type: AclType::IPV4,
                ace: vec![Ace {
                    name: "some_ace_name".to_string(),
                    action: AceAction::Accept,
                    matches: AceMatches {
                        l3: Some(L3Matches::Ipv4(Ipv4Matches {
                            protocol: Some(AceProtocol::Tcp),
                            src_network: None,
                            dst_network: None,
                            src_dnsname: None,
                            dst_dnsname: None,
                            dscp: None,
                            ecn: None,
                            length: None,
                            ttl: None,
                            ihl: None,
                            flags: None,
                            offset: None,
                            identification: None,
                        })),
                        l4: Some(L4Matches::Tcp(TcpMatches {
                            sequence_number: None,
                            acknowledgement_number: None,
                            data_offset: None,
                            reserved: None,
                            flags: None,
                            window_size: None,
                            urgent_pointer: None,
                            options: None,
                            direction_initiated: None,
                            src_port: Some(AcePort::Single(321)),
                            dst_port: Some(AcePort::Single(500)),
                        })),
                        mud: Some(MudMatches {
                            manufacturer: Some("simple-example.com".to_string()),
                            same_manufacturer: false,
                            controller: None,
                            my_controller: false,
                            local: false,
                            model: None,
                        }),
                    },
                }],
            }],
            acl_override: Vec::default(),
        };

        let device = DeviceWithRefs {
            inner: Device {
                id: 0,
                name: None,
                mac_addr: Some("aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap().into()),
                duid: None,
                ipv4_addr: "127.0.0.1".parse().ok(),
                ipv6_addr: None,
                hostname: "".to_string(),
                vendor_class: "".to_string(),
                mud_url: Some("https://example.com/mud_url.json".to_string()),
                collect_info: true,
                last_interaction: Utc::now().naive_utc(),
                fa_icon: None,
                room_id: None,
                q_bit: false,
            },
            mud_data: Some(mud_data),
            room: None,
            controller_mappings: vec![],
            quarantine_exceptions: vec![],
            flow_scopes: vec![],
        };

        let mud_data1 = MudData {
            url: "https://simple-example.com/.well-known/mud".to_string(),
            masa_url: None,
            last_update: "some_last_update".to_string(),
            systeminfo: Some("some_systeminfo".to_string()),
            mfg_name: Some("some_mfg_name".to_string()),
            model_name: Some("some_model_name".to_string()),
            documentation: Some("some_documentation".to_string()),
            expiration: Utc::now(),
            acllist: vec![Acl {
                name: "some_acl_name".to_string(),
                packet_direction: AclDirection::ToDevice,
                acl_type: AclType::IPV4,
                ace: vec![Ace {
                    name: "some_ace_name".to_string(),
                    action: AceAction::Accept,
                    matches: AceMatches {
                        l3: Some(L3Matches::Ipv4(Ipv4Matches {
                            protocol: Some(AceProtocol::Tcp),
                            src_network: None,
                            dst_network: None,
                            src_dnsname: None,
                            dst_dnsname: None,
                            dscp: None,
                            ecn: None,
                            length: None,
                            ttl: None,
                            ihl: None,
                            flags: None,
                            offset: None,
                            identification: None,
                        })),
                        l4: None,
                        mud: None,
                    },
                }],
            }],
            acl_override: Vec::default(),
        };

        let device1 = DeviceWithRefs {
            inner: Device {
                id: 1,
                name: None,
                mac_addr: Some("aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap().into()),
                duid: None,
                ipv4_addr: "127.0.0.2".parse().ok(),
                ipv6_addr: None,
                hostname: "".to_string(),
                vendor_class: "".to_string(),
                mud_url: Some("https://simple-example.com/mud_url.json".to_string()),
                collect_info: true,
                last_interaction: Utc::now().naive_utc(),
                fa_icon: None,
                room_id: None,
                q_bit: false,
            },
            mud_data: Some(mud_data1),
            room: None,
            controller_mappings: vec![],
            quarantine_exceptions: vec![],
            flow_scopes: vec![],
        };

        let resulting_device = FirewallDevice {
            id: device.id,
            ipv4_addr: device.ipv4_addr,
            ipv6_addr: device.ipv6_addr,
            rules: vec![
                FirewallRule::new(
                    String::from("rule_0"),
                    Some(RuleTargetHost::FirewallDevice),
                    Some(RuleTargetHost::Ip(IpAddr::V4(device1.ipv4_addr.unwrap()))),
                    None,
                    Some(namib_shared::firewall_config::L4Matches::Tcp(
                        namib_shared::firewall_config::TcpMatches::only_ports(
                            Some(PortOrRange::Single(321)),
                            Some(PortOrRange::Single(500)),
                        ),
                    )),
                    Verdict::Accept,
                    ScopeConstraint::None,
                ),
                FirewallRule::new(
                    String::from("rule_default_1"),
                    Some(RuleTargetHost::FirewallDevice),
                    None,
                    None,
                    None,
                    Verdict::Reject,
                    ScopeConstraint::None,
                ),
                FirewallRule::new(
                    String::from("rule_default_2"),
                    None,
                    Some(RuleTargetHost::FirewallDevice),
                    None,
                    None,
                    Verdict::Reject,
                    ScopeConstraint::None,
                ),
            ],
            collect_data: true,
        };

        let x = convert_device_to_fw_rules(&device, &[device.clone(), device1], &AdministrativeContext::default());

        assert_eq!(x, resulting_device);
    }

    #[test]
    fn test_icmp_matching() {
        let mud_data = MudData {
            url: "https://example.com/.well-known/mud".to_string(),
            masa_url: None,
            last_update: "some_last_update".to_string(),
            systeminfo: Some("some_systeminfo".to_string()),
            mfg_name: Some("some_mfg_name".to_string()),
            model_name: Some("some_model_name".to_string()),
            documentation: Some("some_documentation".to_string()),
            expiration: Utc::now(),
            acllist: vec![Acl {
                name: "some_acl_name".to_string(),
                packet_direction: AclDirection::FromDevice,
                acl_type: AclType::IPV4,
                ace: vec![Ace {
                    name: "some_ace_name".to_string(),
                    action: AceAction::Accept,
                    matches: AceMatches {
                        l3: Some(L3Matches::Ipv4(Ipv4Matches {
                            protocol: Some(AceProtocol::Icmp),
                            src_network: None,
                            dst_network: None,
                            src_dnsname: None,
                            dst_dnsname: Some(String::from("www.example.test")),
                            dscp: None,
                            ecn: None,
                            length: None,
                            ttl: None,
                            ihl: None,
                            flags: None,
                            offset: None,
                            identification: None,
                        })),
                        l4: Some(L4Matches::Icmp(IcmpMatches {
                            icmp_type: Some(8),
                            icmp_code: Some(0),
                            rest_of_header: None,
                        })),
                        mud: None,
                    },
                }],
            }],
            acl_override: Vec::default(),
        };

        let device = DeviceWithRefs {
            inner: Device {
                id: 0,
                name: None,
                mac_addr: Some("aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap().into()),
                duid: None,
                ipv4_addr: "127.0.0.1".parse().ok(),
                ipv6_addr: None,
                hostname: "".to_string(),
                vendor_class: "".to_string(),
                mud_url: Some("https://example.com/mud_url.json".to_string()),
                collect_info: true,
                last_interaction: Utc::now().naive_utc(),
                fa_icon: None,
                room_id: None,
                q_bit: false,
            },
            mud_data: Some(mud_data),
            room: None,
            controller_mappings: vec![],
            quarantine_exceptions: vec![],
            flow_scopes: vec![],
        };

        let resulting_device = FirewallDevice {
            id: device.id,
            ipv4_addr: device.ipv4_addr,
            ipv6_addr: device.ipv6_addr,
            rules: vec![
                FirewallRule::new(
                    String::from("rule_0"),
                    Some(RuleTargetHost::FirewallDevice),
                    Some(RuleTargetHost::Hostname(String::from("www.example.test"))),
                    None,
                    Some(namib_shared::firewall_config::L4Matches::Icmp(
                        namib_shared::firewall_config::IcmpMatches {
                            icmp_type: Some(8),
                            icmp_code: Some(0),
                            rest_of_header: None,
                        },
                    )),
                    Verdict::Accept,
                    ScopeConstraint::None,
                ),
                FirewallRule::new(
                    String::from("rule_default_1"),
                    Some(RuleTargetHost::FirewallDevice),
                    None,
                    None,
                    None,
                    Verdict::Reject,
                    ScopeConstraint::None,
                ),
                FirewallRule::new(
                    String::from("rule_default_2"),
                    None,
                    Some(RuleTargetHost::FirewallDevice),
                    None,
                    None,
                    Verdict::Reject,
                    ScopeConstraint::None,
                ),
            ],
            collect_data: true,
        };

        let x = convert_device_to_fw_rules(&device, &[device.clone()], &AdministrativeContext::default());

        assert_eq!(x, resulting_device);
    }

    #[test]
    fn test_q_bit() {
        let mud_data = MudData {
            url: "https://example.com/.well-known/mud".to_string(),
            masa_url: None,
            last_update: "some_last_update".to_string(),
            systeminfo: Some("some_systeminfo".to_string()),
            mfg_name: Some("some_mfg_name".to_string()),
            model_name: Some("some_model_name".to_string()),
            documentation: Some("some_documentation".to_string()),
            expiration: Utc::now(),
            acllist: vec![Acl {
                name: "some_acl_name".to_string(),
                packet_direction: AclDirection::FromDevice,
                acl_type: AclType::IPV4,
                ace: vec![
                    Ace {
                        name: "some_ace_name_1".to_string(),
                        action: AceAction::Accept,
                        matches: AceMatches {
                            l3: Some(L3Matches::Ipv4(Ipv4Matches {
                                protocol: Some(AceProtocol::Icmp),
                                src_network: None,
                                dst_network: None,
                                src_dnsname: None,
                                dst_dnsname: Some(String::from("www.example.test")),
                                dscp: None,
                                ecn: None,
                                length: None,
                                ttl: None,
                                ihl: None,
                                flags: None,
                                offset: None,
                                identification: None,
                            })),
                            l4: Some(L4Matches::Icmp(IcmpMatches {
                                icmp_type: Some(8),
                                icmp_code: Some(0),
                                rest_of_header: None,
                            })),
                            mud: None,
                        },
                    },
                    Ace {
                        name: "some_ace_name_2".to_string(),
                        action: AceAction::Accept,
                        matches: AceMatches {
                            l3: Some(L3Matches::Ipv4(Ipv4Matches {
                                protocol: Some(AceProtocol::Icmp),
                                src_network: None,
                                dst_network: None,
                                src_dnsname: None,
                                dst_dnsname: Some(String::from("www.example.test")),
                                dscp: None,
                                ecn: None,
                                length: None,
                                ttl: None,
                                ihl: None,
                                flags: None,
                                offset: None,
                                identification: None,
                            })),
                            l4: Some(L4Matches::Icmp(IcmpMatches {
                                icmp_type: Some(8),
                                icmp_code: Some(0),
                                rest_of_header: None,
                            })),
                            mud: None,
                        },
                    },
                ],
            }],
            acl_override: Vec::default(),
        };

        let device = DeviceWithRefs {
            inner: Device {
                id: 0,
                name: None,
                mac_addr: Some("aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap().into()),
                duid: None,
                ipv4_addr: "127.0.0.1".parse().ok(),
                ipv6_addr: None,
                hostname: "".to_string(),
                vendor_class: "".to_string(),
                mud_url: Some("https://example.com/mud_url.json".to_string()),
                collect_info: true,
                last_interaction: Utc::now().naive_utc(),
                fa_icon: None,
                room_id: None,
                q_bit: true,
            },
            mud_data: Some(mud_data),
            room: None,
            controller_mappings: vec![],
            quarantine_exceptions: vec![QuarantineException {
                id: 1,
                exception_target: "www.example.test/update-service".to_string(),
                direction: AclDirection::FromDevice,
            }],
            flow_scopes: vec![],
        };

        let resulting_device = FirewallDevice {
            id: device.id,
            ipv4_addr: device.ipv4_addr,
            ipv6_addr: device.ipv6_addr,
            rules: vec![
                FirewallRule::new(
                    String::from("rule_quarantine_exception_0"),
                    Some(RuleTargetHost::FirewallDevice),
                    Some(RuleTargetHost::Hostname("www.example.test/update-service".to_string())),
                    None,
                    None,
                    Verdict::Accept,
                    ScopeConstraint::None,
                ),
                FirewallRule::new(
                    String::from("rule_default_1"),
                    Some(RuleTargetHost::FirewallDevice),
                    None,
                    None,
                    None,
                    Verdict::Reject,
                    ScopeConstraint::None,
                ),
                FirewallRule::new(
                    String::from("rule_default_2"),
                    None,
                    Some(RuleTargetHost::FirewallDevice),
                    None,
                    None,
                    Verdict::Reject,
                    ScopeConstraint::None,
                ),
            ],
            collect_data: true,
        };

        let x = convert_device_to_fw_rules(&device, &[device.clone()], &AdministrativeContext::default());

        assert_eq!(x, resulting_device);
    }
}
