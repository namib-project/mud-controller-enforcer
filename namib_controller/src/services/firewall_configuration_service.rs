// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::net::IpAddr;

use namib_shared::{
    firewall_config::{FirewallDevice, FirewallRule, Protocol, RuleName, RuleTarget, RuleTargetHost, Verdict},
    EnforcerConfig,
};

use crate::{
    db::DbConnection,
    error::Result,
    models::{AceAction, AcePort, AceProtocol, Acl, AclDirection, DeviceWithRefs},
    services::{
        acme_service,
        config_service::{get_config_value, set_config_value, ConfigKeys},
    },
};

pub fn merge_acls<'a>(original: &'a [Acl], override_with: &'a [Acl]) -> Vec<&'a Acl> {
    let override_keys: Vec<&str> = override_with.iter().map(|x| x.name.as_ref()).collect();
    original
        .iter()
        .filter(|x| !override_keys.contains(&x.name.as_str()))
        .chain(override_with.iter())
        .collect()
}

pub fn create_configuration(version: String, devices: &[DeviceWithRefs]) -> EnforcerConfig {
    let rules = devices
        .iter()
        .filter(|d| d.ipv4_addr.is_some() || d.ipv6_addr.is_some())
        .map(|d| convert_device_to_fw_rules(d, devices))
        .collect();
    EnforcerConfig::new(version, rules, acme_service::DOMAIN.clone())
}

pub fn convert_device_to_fw_rules(device: &DeviceWithRefs, _devices: &[DeviceWithRefs]) -> FirewallDevice {
    let mut rule_counter = 0;
    let mut rules: Vec<FirewallRule> = Vec::new();
    let mud_data = match &device.mud_data {
        Some(mud_data) => mud_data,
        None => {
            return FirewallDevice {
                id: device.id,
                ipv4_addr: device.ipv4_addr,
                ipv6_addr: device.ipv6_addr,
                rules,
                collect_data: device.collect_info,
            }
        }
    };

    let merged_acls = if mud_data.acl_override.is_empty() {
        mud_data.acllist.iter().collect()
    } else {
        merge_acls(&mud_data.acllist, &mud_data.acl_override)
    };

    for acl in &merged_acls {
        for ace in &acl.ace {
            let protocol = match &ace.matches.protocol {
                None => Protocol::All,
                Some(proto) => match proto {
                    AceProtocol::Tcp => Protocol::Tcp,
                    AceProtocol::Udp => Protocol::Udp,
                    AceProtocol::Protocol(_proto_nr) => Protocol::All, // Default to all protocols if protocol is not supported.
                                                                       // TODO add support for more protocols
                },
            };
            let verdict = match ace.action {
                AceAction::Accept => Verdict::Accept,
                AceAction::Deny => Verdict::Reject,
            };

            let src_ports: Option<String> = match ace.matches.source_port {
                None => None,
                Some(AcePort::Single(port)) => Some(port.to_string()),
                Some(AcePort::Range(from, to)) => Some(format!("{}:{}", from, to)),
            };
            let dst_ports: Option<String> = match ace.matches.destination_port {
                None => None,
                Some(AcePort::Single(port)) => Some(port.to_string()),
                Some(AcePort::Range(from, to)) => Some(format!("{}:{}", from, to)),
            };

            let (this_device_ports, other_device_ports) = match acl.packet_direction {
                AclDirection::FromDevice => (src_ports, dst_ports),
                AclDirection::ToDevice => (dst_ports, src_ports),
            };

            let this_dev_rule_target = RuleTarget::new(Some(RuleTargetHost::FirewallDevice), this_device_ports);

            let other_dev_rule_targets: Vec<RuleTarget> =
                match (&ace.matches.dnsname, &ace.matches.matches_augmentation) {
                    // NOTE: `dns_name` has YANG type 'inet:host' which _can_ be an IP address
                    (Some(dns_name), None) => match dns_name.parse::<IpAddr>() {
                        Ok(addr) => vec![Some(RuleTargetHost::Ip(addr))],
                        Err(_) => vec![Some(RuleTargetHost::Hostname(dns_name.clone()))],
                    },
                    (None, Some(augmentation)) => {
                        let mut targets_per_option: Vec<Vec<Option<RuleTargetHost>>> = Vec::new();
                        if let Some(_host) = &augmentation.manufacturer {
                            // TODO
                        }
                        if augmentation.same_manufacturer {
                            // TODO
                        }
                        if let Some(_uri) = &augmentation.controller {
                            // TODO
                        }
                        if augmentation.my_controller {
                            // TODO
                        }
                        if augmentation.local {
                            // TODO
                        }
                        if augmentation.model {
                            // TODO
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
                    }
                    _ => vec![],
                }
                .iter()
                .map(|host| RuleTarget::new(host.clone(), other_device_ports.clone()))
                .collect();

            for other_dev_rule_target in &other_dev_rule_targets {
                let (src, dst) = match acl.packet_direction {
                    AclDirection::FromDevice => (&this_dev_rule_target, other_dev_rule_target),
                    AclDirection::ToDevice => (other_dev_rule_target, &this_dev_rule_target),
                };
                rules.push(FirewallRule::new(
                    RuleName::new(format!("rule_{}", rule_counter)),
                    src.clone(),
                    dst.clone(),
                    protocol.clone(),
                    verdict.clone(),
                ));
                rule_counter += 1;
            }
        }
    }
    rules.push(FirewallRule::new(
        RuleName::new(format!("rule_default_{}", rule_counter)),
        RuleTarget::new(Some(RuleTargetHost::FirewallDevice), None),
        RuleTarget::new(None, None),
        Protocol::All,
        Verdict::Reject,
    ));
    rule_counter += 1;
    rules.push(FirewallRule::new(
        RuleName::new(format!("rule_default_{}", rule_counter)),
        RuleTarget::new(None, None),
        RuleTarget::new(Some(RuleTargetHost::FirewallDevice), None),
        Protocol::All,
        Verdict::Reject,
    ));

    FirewallDevice {
        id: device.id,
        ipv4_addr: device.ipv4_addr,
        ipv6_addr: device.ipv6_addr,
        rules,
        collect_data: device.collect_info,
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

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use namib_shared::macaddr::MacAddr;

    use super::*;
    use crate::models::{Ace, AceAction, AceMatches, AceProtocol, Acl, AclDirection, AclType, Device, MudData};
    use crate::models::MudAclMatchesAugmentation::SameManufacturer;

    #[test]
    fn test_acl_merging() -> Result<()> {
        let original_acls = vec![
            Acl {
                name: "acl_to_device".to_string(),
                packet_direction: AclDirection::ToDevice,
                acl_type: AclType::IPV6,
                ace: vec![Ace {
                    name: "acl_to_device_0".to_string(),
                    action: AceAction::Accept,
                    matches: AceMatches {
                        protocol: Some(AceProtocol::Tcp),
                        direction_initiated: None,
                        address_mask: None,
                        dnsname: None,
                        source_port: None,
                        destination_port: None,
                        matches_augmentation: None,
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
                        protocol: Some(AceProtocol::Tcp),
                        direction_initiated: None,
                        address_mask: None,
                        dnsname: None,
                        source_port: None,
                        destination_port: None,
                        matches_augmentation: None,
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
                        protocol: Some(AceProtocol::Tcp),
                        direction_initiated: None,
                        address_mask: None,
                        dnsname: None,
                        source_port: None,
                        destination_port: None,
                        matches_augmentation: None,
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
                        protocol: Some(AceProtocol::Udp),
                        direction_initiated: None,
                        address_mask: None,
                        dnsname: None,
                        source_port: None,
                        destination_port: None,
                        matches_augmentation: None,
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

        Ok(())
    }

    #[test]
    fn test_overridden_acls_to_firewall_rules() -> Result<()> {
        let mud_data = MudData {
            url: "example.com/.well-known/mud".to_string(),
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
                        protocol: Some(AceProtocol::Tcp),
                        direction_initiated: None,
                        address_mask: None,
                        dnsname: Some(String::from("www.example.test")),
                        source_port: None,
                        destination_port: None,
                        matches_augmentation: None,
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
                        protocol: Some(AceProtocol::Udp),
                        direction_initiated: None,
                        address_mask: None,
                        dnsname: Some(String::from("www.example.test")),
                        source_port: None,
                        destination_port: None,
                        matches_augmentation: None,
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
                mud_url: Some("http://example.com/mud_url.json".to_string()),
                last_interaction: Utc::now().naive_utc(),
                collect_info: false,
                clipart: None,
                room_id: None,
            },
            mud_data: Some(mud_data),
            room: None,
        };

        let x = convert_device_to_fw_rules(&device, &[device.clone()]);

        let resulting_device = FirewallDevice {
            id: device.id,
            ipv4_addr: device.ipv4_addr,
            ipv6_addr: device.ipv6_addr,
            rules: vec![
                FirewallRule::new(
                    RuleName::new(String::from("rule_0")),
                    RuleTarget::new(Some(RuleTargetHost::Hostname(String::from("www.example.test"))), None),
                    RuleTarget::new(Some(RuleTargetHost::FirewallDevice), None),
                    Protocol::Udp,
                    Verdict::Reject,
                ),
                FirewallRule::new(
                    RuleName::new(String::from("rule_default_1")),
                    RuleTarget::new(Some(RuleTargetHost::FirewallDevice), None),
                    RuleTarget::new(None, None),
                    Protocol::All,
                    Verdict::Reject,
                ),
                FirewallRule::new(
                    RuleName::new(String::from("rule_default_2")),
                    RuleTarget::new(None, None),
                    RuleTarget::new(Some(RuleTargetHost::FirewallDevice), None),
                    Protocol::All,
                    Verdict::Reject,
                ),
            ],
            collect_data: false,
        };

        assert!(x.eq(&resulting_device));

        Ok(())
    }

    #[test]
    fn test_converting() -> Result<()> {
        let mud_data = MudData {
            url: "example.com/.well-known/mud".to_string(),
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
                            protocol: Some(AceProtocol::Tcp),
                            direction_initiated: None,
                            address_mask: None,
                            dnsname: Some(String::from("www.example.test")),
                            source_port: Some(AcePort::Single(123)),
                            destination_port: Some(AcePort::Range(50, 60)),
                            matches_augmentation: None,
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
                            protocol: Some(AceProtocol::Udp),
                            direction_initiated: None,
                            address_mask: None,
                            dnsname: Some(String::from("www.example.test")),
                            source_port: Some(AcePort::Range(8000, 8080)),
                            destination_port: Some(AcePort::Single(56)),
                            matches_augmentation: None,
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
                mud_url: Some("http://example.com/mud_url.json".to_string()),
                collect_info: true,
                last_interaction: Utc::now().naive_utc(),
                clipart: None,
                room_id: None,
            },
            mud_data: Some(mud_data),
            room: None,
        };

        let x = convert_device_to_fw_rules(&device, &[device.clone()]);

        let resulting_device = FirewallDevice {
            id: device.id,
            ipv4_addr: device.ipv4_addr,
            ipv6_addr: device.ipv6_addr,
            rules: vec![
                FirewallRule::new(
                    RuleName::new(String::from("rule_0")),
                    RuleTarget::new(
                        Some(RuleTargetHost::Hostname(String::from("www.example.test"))),
                        Some("123".to_string()),
                    ),
                    RuleTarget::new(Some(RuleTargetHost::FirewallDevice), Some("50:60".to_string())),
                    Protocol::Tcp,
                    Verdict::Accept,
                ),
                FirewallRule::new(
                    RuleName::new(String::from("rule_1")),
                    RuleTarget::new(Some(RuleTargetHost::FirewallDevice), Some("8000:8080".to_string())),
                    RuleTarget::new(
                        Some(RuleTargetHost::Hostname(String::from("www.example.test"))),
                        Some("56".to_string()),
                    ),
                    Protocol::Udp,
                    Verdict::Accept,
                ),
                FirewallRule::new(
                    RuleName::new(String::from("rule_default_2")),
                    RuleTarget::new(Some(RuleTargetHost::FirewallDevice), None),
                    RuleTarget::new(None, None),
                    Protocol::All,
                    Verdict::Reject,
                ),
                FirewallRule::new(
                    RuleName::new(String::from("rule_default_3")),
                    RuleTarget::new(None, None),
                    RuleTarget::new(Some(RuleTargetHost::FirewallDevice), None),
                    Protocol::All,
                    Verdict::Reject,
                ),
            ],
            collect_data: true,
        };

        assert!(x.eq(&resulting_device));

        Ok(())
    }

    #[test]
    fn test_same_manufacturer() -> Result<()> {
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
                        protocol: Some(AceProtocol::Tcp),
                        direction_initiated: None,
                        address_mask: None,
                        dnsname: Some(String::from("www.example.test")),
                        source_port: None,
                        destination_port: None,
                        matches_augmentation: Some(SameManufacturer),
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
                mud_url: None,
                collect_info: true,
                last_interaction: Utc::now().naive_utc(),
                clipart: None,
                room_id: None,
            },
            mud_data: Some(mud_data),
            room: None,
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
                        protocol: Some(AceProtocol::Tcp),
                        direction_initiated: None,
                        address_mask: None,
                        dnsname: None,
                        source_port: None,
                        destination_port: None,
                        matches_augmentation: Some(SameManufacturer),
                    },
                }],
            }],
            acl_override: Vec::default(),
        };

        let device1 = DeviceWithRefs {
            inner: Device {
                id: 0,
                name: None,
                mac_addr: Some("aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap().into()),
                duid: None,
                ipv4_addr: "127.0.0.2".parse().ok(),
                ipv6_addr: None,
                hostname: "".to_string(),
                vendor_class: "".to_string(),
                mud_url: Some("http://example.com/mud_url.json".to_string()),
                collect_info: true,
                last_interaction: Utc::now().naive_utc(),
                clipart: None,
                room_id: None,
            },
            mud_data: Some(mud_data1),
            room: None,
        };

        let device1ip = device1.ipv4_addr.unwrap();

        let x = convert_device_to_fw_rules(&device, &[device1]);


        let resulting_device = FirewallDevice {
            id: device.id,
            ipv4_addr: device.ipv4_addr,
            ipv6_addr: device.ipv6_addr,
            rules: vec![
                FirewallRule::new(
                    RuleName::new(String::from("rule_0")),
                    RuleTarget::new(Some(RuleTargetHost::FirewallDevice), None),
                    RuleTarget::new(Some(RuleTargetHost::Ip(IpAddr::V4(device1ip))), None),
                    Protocol::Tcp,
                    Verdict::Accept,
                ),
                FirewallRule::new(
                    RuleName::new(String::from("rule_default_1")),
                    RuleTarget::new(Some(RuleTargetHost::FirewallDevice), None),
                    RuleTarget::new(None, None),
                    Protocol::All,
                    Verdict::Reject,
                ),
                FirewallRule::new(
                    RuleName::new(String::from("rule_default_2")),
                    RuleTarget::new(None, None),
                    RuleTarget::new(Some(RuleTargetHost::FirewallDevice), None),
                    Protocol::All,
                    Verdict::Reject,
                ),
            ],
            collect_data: true,
        };
        assert!(x.eq(&resulting_device));

        Ok(())
    }
}
