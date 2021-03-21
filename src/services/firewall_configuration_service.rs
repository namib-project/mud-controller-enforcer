use crate::{
    db::DbConnection,
    error::Result,
    models::{AceAction, AceProtocol, Acl, AclDirection, Device},
    services::{
        acme_service,
        config_service::{get_config_value, set_config_value, ConfigKeys},
    },
};
use namib_shared::firewall_config::{
    EnforcerConfig, FirewallDevice, FirewallRule, NetworkConfig, NetworkHost, Protocol, RuleName, Target,
};
use std::net::IpAddr;

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

pub fn create_configuration(version: String, devices: Vec<Device>) -> EnforcerConfig {
    let rules: Vec<FirewallDevice> = devices.iter().map(move |d| convert_device_to_fw_rules(d)).collect();
    EnforcerConfig::new(version, rules, acme_service::DOMAIN.clone())
}

pub fn convert_device_to_fw_rules(device: &Device) -> FirewallDevice {
    let mut index = 0;
    let mut result: Vec<FirewallRule> = Vec::new();
    let mud_data = match &device.mud_data {
        Some(mud_data) => mud_data,
        None => return FirewallDevice::new(device.id, device.ip_addr, result, device.collect_info),
    };

    let merged_acls = match &mud_data.acl_override {
        Some(acl_override) => merge_acls(&mud_data.acllist, acl_override),
        None => (&mud_data.acllist).iter().collect::<Vec<&Acl>>(),
    };

    for acl in &merged_acls {
        for ace in &acl.ace {
            let rule_name = RuleName::new(format!("rule_{}", index));
            let protocol = match &ace.matches.protocol {
                None => Protocol::All,
                Some(proto) => match proto {
                    AceProtocol::Tcp => Protocol::Tcp,
                    AceProtocol::Udp => Protocol::Udp,
                    AceProtocol::Protocol(_proto_nr) => Protocol::All, // Default to all protocols if protocol is not supported.
                                                                       // TODO add support for more protocols
                },
            };
            let target = match ace.action {
                AceAction::Accept => Target::Accept,
                AceAction::Deny => Target::Reject,
            };

            let route_network_fw_device = NetworkConfig::new(Some(NetworkHost::FirewallDevice), None);
            if let Some(dns_name) = &ace.matches.dnsname {
                let route_network_remote_host = match dns_name.parse::<IpAddr>() {
                    Ok(addr) => NetworkConfig::new(Some(NetworkHost::Ip(addr)), None),
                    _ => NetworkConfig::new(Some(NetworkHost::Hostname(dns_name.clone())), None),
                };

                let (route_network_src, route_network_dest) = match acl.packet_direction {
                    AclDirection::FromDevice => (route_network_fw_device, route_network_remote_host),
                    AclDirection::ToDevice => (route_network_remote_host, route_network_fw_device),
                };
                let config_firewall = FirewallRule::new(
                    rule_name.clone(),
                    route_network_src,
                    route_network_dest,
                    protocol.clone(),
                    target.clone(),
                );
                result.push(config_firewall);
            }
            index += 1;
        }
    }
    result.push(FirewallRule::new(
        RuleName::new(format!("rule_default_{}", index)),
        NetworkConfig::new(Some(NetworkHost::FirewallDevice), None),
        NetworkConfig::new(None, None),
        Protocol::All,
        Target::Reject,
    ));
    index += 1;
    result.push(FirewallRule::new(
        RuleName::new(format!("rule_default_{}", index)),
        NetworkConfig::new(None, None),
        NetworkConfig::new(Some(NetworkHost::FirewallDevice), None),
        Protocol::All,
        Target::Reject,
    ));

    FirewallDevice::new(device.id, device.ip_addr, result, device.collect_info)
}

pub async fn get_config_version(pool: &DbConnection) -> String {
    get_config_value(ConfigKeys::Version.as_ref(), pool)
        .await
        .unwrap_or_else(|_| "0".to_string())
}

pub async fn update_config_version(pool: &DbConnection) -> Result<()> {
    let old_config_version = get_config_value(ConfigKeys::Version.as_ref(), pool).await.unwrap_or(0);
    set_config_value(ConfigKeys::Version.as_ref(), old_config_version + 1, pool).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use namib_shared::mac;

    use crate::models::{Ace, AceAction, AceMatches, AceProtocol, Acl, AclDirection, AclType, Device, MudData};

    use super::*;

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
                        protocol: Some(AceProtocol::Tcp),
                        direction_initiated: None,
                        address_mask: None,
                        dnsname: Some(String::from("www.example.test")),
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
                        protocol: Some(AceProtocol::Udp),
                        direction_initiated: None,
                        address_mask: None,
                        dnsname: Some(String::from("www.example.test")),
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
            collect_info: false,
            clipart: None,
        };

        let x = convert_device_to_fw_rules(&device);

        println!("{:#?}", x);

        let resulting_device = FirewallDevice::new(
            device.id,
            device.ip_addr,
            vec![
                FirewallRule::new(
                    RuleName::new(String::from("rule_0")),
                    NetworkConfig::new(Some(NetworkHost::Hostname(String::from("www.example.test"))), None),
                    NetworkConfig::new(Some(NetworkHost::FirewallDevice), None),
                    Protocol::Udp,
                    Target::Reject,
                ),
                FirewallRule::new(
                    RuleName::new(String::from("rule_default_1")),
                    NetworkConfig::new(Some(NetworkHost::FirewallDevice), None),
                    NetworkConfig::new(None, None),
                    Protocol::All,
                    Target::Reject,
                ),
                FirewallRule::new(
                    RuleName::new(String::from("rule_default_2")),
                    NetworkConfig::new(None, None),
                    NetworkConfig::new(Some(NetworkHost::FirewallDevice), None),
                    Protocol::All,
                    Target::Reject,
                ),
            ],
            false,
        );

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
            collect_info: true,
            mud_data: Some(mud_data),
            last_interaction: Utc::now().naive_local(),
            clipart: None,
        };

        let x = convert_device_to_fw_rules(&device);

        println!("{:#?}", x);

        let resulting_device = FirewallDevice::new(
            device.id,
            device.ip_addr,
            vec![
                FirewallRule::new(
                    RuleName::new(String::from("rule_0")),
                    NetworkConfig::new(Some(NetworkHost::Hostname(String::from("www.example.test"))), None),
                    NetworkConfig::new(Some(NetworkHost::FirewallDevice), None),
                    Protocol::Tcp,
                    Target::Accept,
                ),
                FirewallRule::new(
                    RuleName::new(String::from("rule_default_1")),
                    NetworkConfig::new(Some(NetworkHost::FirewallDevice), None),
                    NetworkConfig::new(None, None),
                    Protocol::All,
                    Target::Reject,
                ),
                FirewallRule::new(
                    RuleName::new(String::from("rule_default_2")),
                    NetworkConfig::new(None, None),
                    NetworkConfig::new(Some(NetworkHost::FirewallDevice), None),
                    Protocol::All,
                    Target::Reject,
                ),
            ],
            true,
        );

        assert!(x.eq(&resulting_device));

        Ok(())
    }
}
