use crate::{
    db::DbConnPool,
    error::Result,
    models::{
        device_model::DeviceData,
        mud_models::{ACEAction, ACEProtocol, ACLDirection, ACLType},
    },
};
use namib_shared::config_firewall::{EnNetwork, EnTarget, FirewallRule, Protocol, RuleName};
use std::{
    net::{IpAddr, ToSocketAddrs},
    sync::atomic::{AtomicU32, Ordering},
};

static VERSION: AtomicU32 = AtomicU32::new(0);

pub fn convert_device_to_fw_rules(device: &DeviceData) -> Result<Vec<FirewallRule>> {
    let mut index = 0;
    let mut result: Vec<FirewallRule> = Vec::new();
    let mud_data = match &device.mud_data {
        Some(mud_data) => mud_data,
        None => return Ok(result),
    };

    for acl in &mud_data.acllist {
        for ace in &acl.ace {
            let rule_name = RuleName::new(format!("rule_{}", index));
            let (route_network_src, route_network_dest) = match acl.packet_direction {
                ACLDirection::FromDevice => (EnNetwork::LAN, EnNetwork::WAN),
                ACLDirection::ToDevice => (EnNetwork::WAN, EnNetwork::LAN),
            };
            let protocol = match &ace.matches.protocol {
                None => Protocol::all(),
                Some(proto) => match proto {
                    ACEProtocol::TCP => Protocol::tcp(),
                    ACEProtocol::UDP => Protocol::udp(),
                    ACEProtocol::Protocol(proto_nr) => Protocol::from_number(proto_nr.to_owned()),
                },
            };
            let target = match ace.action {
                ACEAction::Accept => EnTarget::ACCEPT,
                ACEAction::Deny => EnTarget::REJECT,
            };

            if let Some(dnsname) = &ace.matches.dnsname {
                let socket_addresses = match format!("{}:443", dnsname).to_socket_addrs() {
                    Ok(socket) => socket,
                    Err(_) => Vec::new().into_iter(),
                };
                for addr in socket_addresses {
                    match addr.ip() {
                        IpAddr::V4(_) => {
                            if acl.acl_type == ACLType::IPV6 {
                                continue;
                            }
                        },
                        IpAddr::V6(_) => {
                            if acl.acl_type == ACLType::IPV4 {
                                continue;
                            }
                        },
                    };
                    let (src_ip, dest_ip) = match acl.packet_direction {
                        ACLDirection::FromDevice => (device.ip_addr.to_string(), addr.ip().to_string()),
                        ACLDirection::ToDevice => (addr.ip().to_string(), device.ip_addr.to_string()),
                    };
                    let config_firewall = FirewallRule::new(
                        rule_name.clone(),
                        route_network_src.clone(),
                        route_network_dest.clone(),
                        protocol.clone(),
                        target.clone(),
                        Some(vec![("src_ip".to_string(), src_ip), ("dest_ip".to_string(), dest_ip)]),
                    );
                    result.push(config_firewall);
                }
            } else {
                let config_firewall = FirewallRule::new(
                    rule_name,
                    route_network_src,
                    route_network_dest,
                    protocol,
                    target,
                    Some(vec![(
                        match acl.packet_direction {
                            ACLDirection::FromDevice => "src_ip".to_string(),
                            ACLDirection::ToDevice => "dest_ip".to_string(),
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
        EnNetwork::LAN,
        EnNetwork::WAN,
        Protocol::all(),
        EnTarget::REJECT,
        Some(vec![("src_ip".to_string(), device.ip_addr.to_string())]),
    ));
    index += 1;
    result.push(FirewallRule::new(
        RuleName::new(format!("rule_default_{}", index)),
        EnNetwork::WAN,
        EnNetwork::LAN,
        Protocol::all(),
        EnTarget::REJECT,
        Some(vec![("dest_ip".to_string(), device.ip_addr.to_string())]),
    ));

    Ok(result)
}

pub async fn get_config_version(_: DbConnPool) -> String {
    VERSION.load(Ordering::SeqCst).to_string()
}

pub async fn update_config_version(_: DbConnPool) {
    VERSION.fetch_add(1, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        device_model::DeviceData,
        mud_models::{ACEAction, ACEMatches, ACEProtocol, ACLDirection, ACLType, MUDData, ACE, ACL},
    };
    use chrono::Local;
    use namib_shared::macaddr;

    #[test]
    fn test_converting() -> Result<()> {
        let mud_data = MUDData {
            url: "example.com/.well-known/mud".to_string(),
            masa_url: None,
            last_update: "some_last_update".to_string(),
            systeminfo: Some("some_systeminfo".to_string()),
            mfg_name: Some("some_mfg_name".to_string()),
            model_name: Some("some_model_name".to_string()),
            documentation: Some("some_documentation".to_string()),
            expiration: Local::now(),
            acllist: vec![ACL {
                name: "some_acl_name".to_string(),
                packet_direction: ACLDirection::ToDevice,
                acl_type: ACLType::IPV6,
                ace: vec![ACE {
                    name: "some_ace_name".to_string(),
                    action: ACEAction::Accept,
                    matches: ACEMatches {
                        protocol: Some(ACEProtocol::TCP),
                        direction_initiated: None,
                        address_mask: None,
                        dnsname: None,
                        source_port: None,
                        destination_port: None,
                    },
                }],
            }],
        };

        let device = DeviceData {
            id: 0,
            mac_addr: Some("aa:bb:cc:dd:ee:ff".parse::<macaddr::MacAddr>().unwrap().into()),
            ip_addr: "127.0.0.1".parse().unwrap(),
            hostname: "".to_string(),
            vendor_class: "".to_string(),
            mud_url: Some("http://example.com/mud_url.json".to_string()),
            mud_data: Some(mud_data),
            last_interaction: Local::now().naive_local(),
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
