use crate::{
    db::DbConnection,
    error::Result,
    models::{AceAction, AceProtocol, AclDirection, AclType, Device},
    services::config_service::{get_config_value, set_config_value, ConfigKeys},
};
use namib_shared::firewall_config::{
    EnforcerConfig, FirewallRule, KnownDevice, Network, NetworkConfig, Protocol, RuleName, Target,
};
use std::net::{IpAddr, ToSocketAddrs};

pub fn create_configuration(version: String, devices: Vec<Device>) -> EnforcerConfig {
    let rules: Vec<FirewallRule> = devices
        .iter()
        .flat_map(move |d| {
            convert_device_to_fw_rules(d)
                .map_err(|err| error!("Flat Map Error {:#?}", err))
                .unwrap_or_default()
        })
        .collect();
    EnforcerConfig::new(
        version,
        rules,
        devices
            .into_iter()
            .map(|d| KnownDevice::new(d.ip_addr, d.collect_info))
            .collect(),
    )
}

pub fn convert_device_to_fw_rules(device: &Device) -> Result<Vec<FirewallRule>> {
    let mut index = 0;
    let mut result: Vec<FirewallRule> = Vec::new();
    let mud_data = match &device.mud_data {
        Some(mud_data) => mud_data,
        None => return Ok(result),
    };

    for acl in &mud_data.acllist {
        for ace in &acl.ace {
            let rule_name = RuleName::new(format!("rule_{}", index));
            let protocol = match &ace.matches.protocol {
                None => Protocol::all(),
                Some(proto) => match proto {
                    AceProtocol::Tcp => Protocol::tcp(),
                    AceProtocol::Udp => Protocol::udp(),
                    AceProtocol::Protocol(proto_nr) => Protocol::from_number(proto_nr.to_owned()),
                },
            };
            let target = match ace.action {
                AceAction::Accept => Target::ACCEPT,
                AceAction::Deny => Target::REJECT,
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
                    let route_network_lan = NetworkConfig::new(Network::LAN, Some(device.ip_addr.to_string()), None);
                    let route_network_wan = NetworkConfig::new(Network::WAN, Some(addr.ip().to_string()), None);
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
                let route_network_lan = NetworkConfig::new(Network::LAN, None, None);
                let route_network_wan = NetworkConfig::new(Network::WAN, None, None);
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
        NetworkConfig::new(Network::LAN, Some(device.ip_addr.to_string()), None),
        NetworkConfig::new(Network::WAN, None, None),
        Protocol::all(),
        Target::REJECT,
        None,
    ));
    index += 1;
    result.push(FirewallRule::new(
        RuleName::new(format!("rule_default_{}", index)),
        NetworkConfig::new(Network::WAN, None, None),
        NetworkConfig::new(Network::LAN, Some(device.ip_addr.to_string()), None),
        Protocol::all(),
        Target::REJECT,
        Some(vec![("dest_ip".to_string(), device.ip_addr.to_string())]),
    ));

    Ok(result)
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
                        dnsname: None,
                        source_port: None,
                        destination_port: None,
                    },
                }],
            }],
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
