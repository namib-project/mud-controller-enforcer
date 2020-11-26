use crate::{
    error::*,
    models::mud_models::{ACLDirection, *},
    services::device_service::Device,
};
use namib_shared::config_firewall::*;
use std::net::{IpAddr, ToSocketAddrs};

pub fn convert_device_to_fw_rules(device: &Device) -> Result<Vec<FirewallRule>> {
    let mut index = 0;
    let mut result: Vec<FirewallRule> = Vec::new();
    let mud_data = &device.mud_data;
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
                let socket_addresses = format!("{}:443", dnsname).to_socket_addrs()?;
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
                    let config_firewall = FirewallRule::new(
                        rule_name.clone(),
                        route_network_src.clone(),
                        route_network_dest.clone(),
                        protocol.clone(),
                        target.clone(),
                        Some(vec![("dest_ip".to_string(), addr.ip().to_string())]),
                    );
                    result.push(config_firewall);
                }
            } else {
                let config_firewall = FirewallRule::new(rule_name, route_network_src, route_network_dest, protocol, target, None);
                result.push(config_firewall);
            }
            index += 1;
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::mud_models::*;
    use chrono::Local;
    use std::net::Ipv4Addr;

    #[test]
    fn test_converting() -> Result<()> {
        let mud_data = MUDData {
            url: "example.com/.well-known/mud".to_string(),
            masa_url: None,
            last_update: "some_last_update".to_string(),
            systeminfo: "some_systeminfo".to_string(),
            mfg_name: "some_mfg_name".to_string(),
            model_name: "some_model_name".to_string(),
            documentation: "some_documentation".to_string(),
            expiration: Local::now(),
            acllist: vec![ACL {
                name: "some_acl_name".to_string(),
                packet_direction: ACLDirection::ToDevice,
                acl_type: ACLType::IPV6,
                ace: vec![ACE {
                    name: "some_ace_name".to_string(),
                    action: ACEAction::Accept,
                    matches: ACEMatches {
                        protocol: None,
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
            mud_url: "".to_string(),
            mac: "".to_string(),
            ip_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            mud_data,
        };

        let x = convert_device_to_fw_rules(&device)?;

        println!("{:#?}", x);

        assert_eq!(x[0].target, EnTarget::ACCEPT);

        Ok(())
    }
}
