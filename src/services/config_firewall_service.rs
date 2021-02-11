use crate::{
    db::DbConnection,
    error::Result,
    models::{AceAction, AceProtocol, Acl, AclDirection, AclType, Device},
    services::config_service::{get_config_value, set_config_value},
};
use namib_shared::config_firewall::{EnNetwork, EnTarget, FirewallRule, NetworkConfig, Protocol, RuleName};
use std::net::{IpAddr, ToSocketAddrs};

pub fn merge_acls<'a>(original: &'a [Acl], override_with: &'a [Acl]) -> Vec<&'a Acl> {
    let override_keys: Vec<&str> = override_with.iter().map(|x| x.name.as_ref()).collect();
    let mut merged_acls: Vec<&Acl> = override_with.iter().collect();
    let mut filtered_original_acls = original
        .iter()
        .filter(|x| !override_keys.contains(&x.name.as_str()))
        .collect::<Vec<&Acl>>();

    merged_acls.append(&mut filtered_original_acls);

    merged_acls
}

pub fn convert_device_to_fw_rules(device: &Device) -> Result<Vec<FirewallRule>> {
    let mut index = 0;
    let mut result: Vec<FirewallRule> = Vec::new();
    let mud_data = match &device.mud_data {
        Some(mud_data) => mud_data,
        None => return Ok(result),
    };

    let merged_acls = match &mud_data.acl_override {
        Some(acl_override) => merge_acls(&mud_data.acllist, acl_override),
        None => (&mud_data.acllist).iter().collect::<Vec<&Acl>>(),
    };

    for acl in merged_acls {
        for ace in &acl.ace {
            let rule_name = RuleName::new(format!("rule_{}", index));
            let protocol = match &ace.matches.protocol {
                None => Protocol::all(),
                Some(proto) => match proto {
                    AceProtocol::TCP => Protocol::tcp(),
                    AceProtocol::UDP => Protocol::udp(),
                    AceProtocol::Protocol(proto_nr) => Protocol::from_number(proto_nr.to_owned()),
                },
            };
            let target = match ace.action {
                AceAction::Accept => EnTarget::ACCEPT,
                AceAction::Deny => EnTarget::REJECT,
            };

            if let Some(dnsname) = &ace.matches.dnsname {
                let socket_addresses = match format!("{}:443", dnsname).to_socket_addrs() {
                    Ok(socket) => socket,
                    Err(_) => Vec::new().into_iter(),
                };
                for addr in socket_addresses {
                    match addr.ip() {
                        IpAddr::V4(_) => {
                            if acl.acl_type == AclType::IPV6 {
                                continue;
                            }
                        },
                        IpAddr::V6(_) => {
                            if acl.acl_type == AclType::IPV4 {
                                continue;
                            }
                        },
                    };
                    let route_network_lan = NetworkConfig::new(EnNetwork::LAN, Some(device.ip_addr.to_string()), None);
                    let route_network_wan = NetworkConfig::new(EnNetwork::WAN, Some(addr.ip().to_string()), None);
                    let (route_network_src, route_network_dest) = match acl.packet_direction {
                        AclDirection::FromDevice => (route_network_lan, route_network_wan),
                        AclDirection::ToDevice => (route_network_wan, route_network_lan),
                    };
                    let config_firewall = FirewallRule::new(
                        rule_name.clone(),
                        route_network_src,
                        route_network_dest,
                        protocol.clone(),
                        target.clone(),
                        None,
                    );
                    result.push(config_firewall);
                }
            } else {
                let route_network_lan = NetworkConfig::new(EnNetwork::LAN, None, None);
                let route_network_wan = NetworkConfig::new(EnNetwork::WAN, None, None);
                let (route_network_src, route_network_dest) = match acl.packet_direction {
                    AclDirection::FromDevice => (route_network_lan, route_network_wan),
                    AclDirection::ToDevice => (route_network_wan, route_network_lan),
                };
                let config_firewall = FirewallRule::new(
                    rule_name,
                    route_network_src,
                    route_network_dest,
                    protocol,
                    target,
                    Some(vec![(
                        match acl.packet_direction {
                            AclDirection::FromDevice => "src_ip".to_string(),
                            AclDirection::ToDevice => "dest_ip".to_string(),
                        },
                        device.ip_addr.to_string(),
                    )]),
                );
                result.push(config_firewall);
            }
            index += 1;
        }
    }
    result.push(FirewallRule::new(
        RuleName::new(format!("rule_default_{}", index)),
        NetworkConfig::new(EnNetwork::LAN, Some(device.ip_addr.to_string()), None),
        NetworkConfig::new(EnNetwork::WAN, None, None),
        Protocol::all(),
        EnTarget::REJECT,
        None,
    ));
    index += 1;
    result.push(FirewallRule::new(
        RuleName::new(format!("rule_default_{}", index)),
        NetworkConfig::new(EnNetwork::WAN, None, None),
        NetworkConfig::new(EnNetwork::LAN, Some(device.ip_addr.to_string()), None),
        Protocol::all(),
        EnTarget::REJECT,
        Some(vec![("dest_ip".to_string(), device.ip_addr.to_string())]),
    ));

    Ok(result)
}

pub async fn get_config_version(pool: &DbConnection) -> String {
    get_config_value("version", pool)
        .await
        .unwrap_or_else(|_| "0".to_string())
}

pub async fn update_config_version(pool: &DbConnection) {
    set_config_value(
        "version",
        &(get_config_value("version", pool)
            .await
            .unwrap_or_else(|_| "0".to_string())
            .parse::<u32>()
            .unwrap_or(1)
            + 1)
        .to_string(),
        pool,
    )
    .await
    .expect("failed to write config");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Ace, AceAction, AceMatches, AceProtocol, Acl, AclDirection, AclType, Device, MudData};
    use chrono::Utc;
    use namib_shared::mac;

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
                        protocol: Some(AceProtocol::TCP),
                        direction_initiated: None,
                        address_mask: None,
                        dnsname: None,
                        source_port: None,
                        destination_port: None,
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
                        protocol: Some(AceProtocol::TCP),
                        direction_initiated: None,
                        address_mask: None,
                        dnsname: None,
                        source_port: None,
                        destination_port: None,
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
                        protocol: Some(AceProtocol::TCP),
                        direction_initiated: None,
                        address_mask: None,
                        dnsname: None,
                        source_port: None,
                        destination_port: None,
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
                        protocol: Some(AceProtocol::UDP),
                        direction_initiated: None,
                        address_mask: None,
                        dnsname: None,
                        source_port: None,
                        destination_port: None,
                    },
                }],
            },
        ];

        let merged_acls = merge_acls(&original_acls, &override_acls);
        println!("Merged: {:#?}", merged_acls);

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
                        protocol: Some(AceProtocol::TCP),
                        direction_initiated: None,
                        address_mask: None,
                        dnsname: None,
                        source_port: None,
                        destination_port: None,
                    },
                }],
            }],
            acl_override: Some(vec![Acl {
                name: "some_acl_name".to_string(),
                packet_direction: AclDirection::ToDevice,
                acl_type: AclType::IPV4,
                ace: vec![Ace {
                    name: "overriden_ace".to_string(),
                    action: AceAction::Deny,
                    matches: AceMatches {
                        protocol: Some(AceProtocol::UDP),
                        direction_initiated: None,
                        address_mask: None,
                        dnsname: None,
                        source_port: None,
                        destination_port: None,
                    },
                }],
            }]),
        };

        let device = Device {
            id: 0,
            mac_addr: Some("aa:bb:cc:dd:ee:ff".parse::<mac::MacAddr>().unwrap().into()),
            ip_addr: "127.0.0.1".parse().unwrap(),
            hostname: "".to_string(),
            vendor_class: "".to_string(),
            mud_url: Some("http://example.com/mud_url.json".to_string()),
            mud_data: Some(mud_data),
            last_interaction: Utc::now().naive_local(),
        };

        let x = convert_device_to_fw_rules(&device)?;

        println!("{:#?}", x);

        let first_rule = x[0].to_option();
        println!("First Rule: {:#?}", first_rule);

        assert!(first_rule.iter().any(|x| x.0 == "name" && x.1 == "rule_0"));
        assert!(first_rule.iter().any(|x| x.0 == "src" && x.1 == "wan"));
        assert!(first_rule.iter().any(|x| x.0 == "dest" && x.1 == "lan"));
        assert!(first_rule.iter().any(|x| x.0 == "dest_ip" && x.1 == "127.0.0.1"));
        assert!(first_rule.iter().any(|x| x.0 == "proto" && x.1 == "17"));
        assert!(first_rule.iter().any(|x| x.0 == "target" && x.1 == "REJECT"));

        Ok(())
    }

    #[test]
    fn test_convert_device_to_firewall_rules() -> Result<()> {
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
                        protocol: Some(AceProtocol::TCP),
                        direction_initiated: None,
                        address_mask: None,
                        dnsname: None,
                        source_port: None,
                        destination_port: None,
                    },
                }],
            }],
            acl_override: None,
        };

        let device = Device {
            id: 0,
            mac_addr: Some("aa:bb:cc:dd:ee:ff".parse::<mac::MacAddr>().unwrap().into()),
            ip_addr: "127.0.0.1".parse().unwrap(),
            hostname: "".to_string(),
            vendor_class: "".to_string(),
            mud_url: Some("http://example.com/mud_url.json".to_string()),
            mud_data: Some(mud_data),
            last_interaction: Utc::now().naive_local(),
        };

        let x = convert_device_to_fw_rules(&device)?;

        println!("{:#?}", x);

        let opts = x[0].to_option();
        assert!(opts.iter().any(|x| x.0 == "name" && x.1 == "rule_0"));
        assert!(opts.iter().any(|x| x.0 == "src" && x.1 == "wan"));
        assert!(opts.iter().any(|x| x.0 == "dest" && x.1 == "lan"));
        assert!(opts.iter().any(|x| x.0 == "dest_ip" && x.1 == "127.0.0.1"));
        assert!(opts.iter().any(|x| x.0 == "proto" && x.1 == "6"));
        assert!(opts.iter().any(|x| x.0 == "target" && x.1 == "ACCEPT"));

        Ok(())
    }
}
