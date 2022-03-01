// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{clone::Clone, net::IpAddr, str::FromStr};

use chrono::{Duration, Utc};
use snafu::ensure;

use super::json_models;
use crate::models::MudAclMatchesAugmentation;
use crate::{
    error,
    error::Result,
    models::{Ace, AceAction, AceMatches, AcePort, AceProtocol, Acl, AclDirection, AclType, MudData},
};

// inspired by https://github.com/CiscoDevNet/MUD-Manager by Cisco
pub fn parse_mud(url: String, json: &str) -> Result<MudData> {
    let mud_json: json_models::MudJson = serde_json::from_str(json)?;

    let mud_data = &mud_json.mud;
    if mud_data.mud_version != 1 {
        error::MudError {
            message: String::from("Unsupported MUD Version"),
        }
        .fail()?;
    }
    let cachevalidity = mud_data.cache_validity.unwrap_or(48);
    ensure!(
        cachevalidity >= 1 && cachevalidity <= 168,
        error::MudError {
            message: String::from("MUD-File has invalid 'cache-validity'")
        }
    );
    let exptime = Utc::now() + Duration::hours(cachevalidity);

    // parse masa
    let mut masa_uri = None;
    if let Some(extensions) = &mud_data.extensions {
        for ext in extensions {
            if ext == "masa" {
                if let Some(masa) = &mud_data.masa_server {
                    masa_uri = Some(masa.clone());
                }
            }
        }
    }
    let mut acllist = Vec::new();
    parse_device_policy(
        &mud_data.from_device_policy,
        &mud_json,
        &mut acllist,
        AclDirection::FromDevice,
    )?;
    parse_device_policy(
        &mud_data.to_device_policy,
        &mud_json,
        &mut acllist,
        AclDirection::ToDevice,
    )?;

    let data = MudData {
        url,
        masa_url: masa_uri,
        last_update: mud_data.last_update.clone(),
        systeminfo: mud_data.systeminfo.clone(),
        mfg_name: mud_data.mfg_name.clone(),
        model_name: mud_data.model_name.clone(),
        documentation: mud_data.documentation.clone(),
        expiration: exptime,
        acllist,
        acl_override: Vec::default(),
    };
    info!(
        "MUD URI <{}> Last Update <{}> System Info <{:?}> Cache-Validity <{}> MASA <{:?}> Expiration <{}>",
        data.url, data.last_update, data.systeminfo, cachevalidity, data.masa_url, exptime
    );

    Ok(data)
}

#[allow(clippy::too_many_lines)]
fn parse_device_policy(
    policy: &json_models::Policy,
    mud_json: &json_models::MudJson,
    acllist: &mut Vec<Acl>,
    dir: AclDirection,
) -> Result<()> {
    for access_list in &policy.access_lists.access_list {
        let mut found = false;
        for aclitem in &mud_json.acls.acl {
            if aclitem.name == access_list.name {
                let mut ace: Vec<Ace> = Vec::new();
                let acl_type = if aclitem.type_field == "ipv4-acl-type" {
                    AclType::IPV4
                } else {
                    AclType::IPV6
                };
                for aceitem in &aclitem.aces.ace {
                    let mut protocol = None;
                    let mut direction_initiated = None;
                    let mut address_mask = None;
                    let mut dnsname = None;
                    let mut source_port = None;
                    let mut destination_port = None;
                    let mut matches_augmentation = None;
                    let mut icmp_type = None;
                    let mut code = None;
                    if let Some(udp) = &aceitem.matches.udp {
                        protocol = Some(AceProtocol::Udp);
                        source_port = udp.source_port.as_ref().and_then(|p| parse_mud_port(p).ok());
                        destination_port = udp.destination_port.as_ref().and_then(|p| parse_mud_port(p).ok());
                    } else if let Some(tcp) = &aceitem.matches.tcp {
                        protocol = Some(AceProtocol::Tcp);
                        if let Some(dir) = &tcp.direction_initiated {
                            direction_initiated = Some(match dir.as_str() {
                                "from-device" => AclDirection::FromDevice,
                                "to-device" => AclDirection::ToDevice,
                                _ => error::MudError {
                                    message: String::from("Invalid direction"),
                                }
                                .fail()?,
                            });
                        }

                        source_port = tcp.source_port.as_ref().and_then(|p| parse_mud_port(p).ok());
                        destination_port = tcp.destination_port.as_ref().and_then(|p| parse_mud_port(p).ok());
                    } else if let Some(icmp) = &aceitem.matches.icmp {
                        protocol = Some(AceProtocol::Icmp);
                        icmp_type = Some(icmp.icmp_type);
                        code = Some(icmp.code);
                    }
                    if let Some(ipv6) = &aceitem.matches.ipv6 {
                        if acl_type != AclType::IPV6 {
                            error::MudError {
                                message: String::from("IPv6 ACE in IPv4 ACL"),
                            }
                            .fail()?;
                        }
                        protocol = ipv6.protocol.map(AceProtocol::Protocol);
                        address_mask = ipv6
                            .source_ipv6_network
                            .as_ref()
                            .or_else(|| ipv6.destination_ipv6_network.as_ref())
                            .and_then(|srcip| IpAddr::from_str(srcip.as_str()).ok());
                        dnsname = ipv6.dst_dnsname.clone().or_else(|| ipv6.src_dnsname.clone());
                    } else if let Some(ipv4) = &aceitem.matches.ipv4 {
                        if acl_type != AclType::IPV4 {
                            error::MudError {
                                message: String::from("IPv4 ACE in IPv6 ACL"),
                            }
                            .fail()?;
                        }
                        protocol = ipv4.protocol.map(AceProtocol::Protocol);
                        address_mask = ipv4
                            .source_ipv4_network
                            .as_ref()
                            .or_else(|| ipv4.destination_ipv4_network.as_ref())
                            .and_then(|srcip| IpAddr::from_str(srcip.as_str()).ok());
                        dnsname = ipv4.dst_dnsname.clone().or_else(|| ipv4.src_dnsname.clone());
                    }
                    if let Some(mud) = &aceitem.matches.mud {
                        let manufacturer = mud.manufacturer.as_ref().map(std::string::ToString::to_string);
                        let same_manufacturer = mud.same_manufacturer.is_some();
                        let controller = mud.controller.as_ref().map(std::string::ToString::to_string);
                        let my_controller = mud.my_controller.is_some();
                        let local = false;
                        let model = mud.model.as_ref().map(std::string::ToString::to_string);
                        if manufacturer.is_some()
                            || same_manufacturer
                            || controller.is_some()
                            || my_controller
                            || local
                            || model.is_some()
                        {
                            matches_augmentation = Some(MudAclMatchesAugmentation {
                                manufacturer,
                                same_manufacturer,
                                controller,
                                my_controller,
                                local,
                                model,
                            });
                        }
                    }
                    ace.push(Ace {
                        name: aceitem.name.clone(),
                        action: if aceitem.actions.forwarding == "accept" {
                            AceAction::Accept
                        } else {
                            AceAction::Deny
                        },
                        matches: AceMatches {
                            protocol,
                            direction_initiated,
                            address_mask: address_mask.map(|a| a.to_string()),
                            dnsname,
                            source_port,
                            destination_port,
                            icmp_type,
                            icmp_code: code,
                            matches_augmentation,
                        },
                    });
                }

                acllist.push(Acl {
                    name: access_list.name.clone(),
                    packet_direction: dir,
                    acl_type,
                    ace,
                });
                found = true;
                break;
            }
        }
        ensure!(
            found,
            error::MudError {
                message: String::from("MUD-File has dangling ACL policy")
            }
        );
    }

    Ok(())
}

fn parse_mud_port(port: &json_models::Port) -> Result<AcePort> {
    match port {
        json_models::Port { port: Some(p), .. } => {
            ensure!(
                port.operator == Some(String::from("eq")),
                error::MudError {
                    message: String::from("Only 'eq' operator is supported")
                }
            );
            Ok(AcePort::Single(*p))
        },
        json_models::Port {
            upper_port: Some(upper_port),
            lower_port: Some(lower_port),
            ..
        } => {
            ensure!(
                port.operator == None,
                error::MudError {
                    message: String::from("No operator for port range")
                }
            );
            Ok(AcePort::Range(*lower_port, *upper_port))
        },
        _ => error::MudError {
            message: String::from("Invalid port definition"),
        }
        .fail()?,
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read};

    use chrono::{offset::TimeZone, NaiveDateTime, Utc};
    use serde_json::Value;

    use super::*;

    #[test]
    fn test_trivial_example() -> Result<()> {
        const URL: &str = "https://lighting.example.com/lightbulb2000";
        let mut mud_data = String::new();
        let mut mud_profile = File::open("tests/mud_tests/MUD-Profile-example.json")?;
        mud_profile.read_to_string(&mut mud_data)?;

        let mud = parse_mud(URL.to_string(), mud_data.as_str())?;

        let matches = AceMatches {
            protocol: None,
            direction_initiated: None,
            address_mask: None,
            dnsname: None,
            source_port: None,
            destination_port: None,
            icmp_type: None,
            icmp_code: None,
            matches_augmentation: Some(MudAclMatchesAugmentation {
                manufacturer: None,
                same_manufacturer: true,
                controller: None,
                my_controller: false,
                local: false,
                model: None,
            }),
        };

        let mut ace_list_f: Vec<Ace> = Vec::new();
        let mut ace = Ace {
            name: "myman0-frdev".to_string(),
            action: AceAction::Accept,
            matches: matches.clone(),
        };

        ace_list_f.push(ace.clone());
        ace.name = "myman1-frdev".to_string();
        ace_list_f.push(ace.clone());
        ace_list_f.push(ace.clone());
        ace.name = "myman2-frdev".to_string();
        ace_list_f.push(ace);

        let mut ace_list_t: Vec<Ace> = Vec::new();
        let mut ace = Ace {
            name: "myman0-todev".to_string(),
            action: AceAction::Accept,
            matches,
        };

        ace_list_t.push(ace.clone());
        ace.name = "myman1-todev".to_string();
        ace_list_t.push(ace.clone());
        ace_list_t.push(ace.clone());
        ace.name = "myman2-todev".to_string();
        ace_list_t.push(ace);

        let mut acl_list = Vec::new();
        let mut acl = Acl {
            name: "mud-52892-v4fr".to_string(),
            packet_direction: AclDirection::FromDevice,
            acl_type: AclType::IPV6,
            ace: ace_list_f,
        };

        acl_list.push(acl.clone());
        acl.name = "mud-52892-v4to".to_string();
        acl.packet_direction = AclDirection::ToDevice;
        acl.ace = ace_list_t;

        acl_list.push(acl);
        let example = MudData {
            url: URL.to_string(),
            masa_url: None,
            last_update: "2019-07-23T19:54:24".to_string(),
            systeminfo: Some("The BMS Example Light Bulb".to_string()),
            mfg_name: None,
            model_name: None,
            documentation: Some("https://lighting.example.com/lightbulb2000/documentation".to_string()),
            expiration: mud.expiration,
            acllist: acl_list,
            acl_override: Vec::default(),
        };

        assert_eq!(mud, example);
        Ok(())
    }

    #[test]
    fn test_example_amazon_echo() -> Result<()> {
        compare_mud_accept(
            "tests/mud_tests/Amazon-Echo.json",
            "https://amazonecho.com/amazonecho",
            "tests/mud_tests/Amazon-Echo-Test.json",
        )
    }

    #[test]
    fn test_example_amazon_echo_wrong_expired() -> Result<()> {
        compare_mud_fail(
            "tests/mud_tests/Amazon-Echo.json",
            "https://amazonecho.com/amazonecho",
            "tests/mud_tests/Amazon-Echo-Test.json",
        )
    }

    #[test]
    fn test_example_ring_doorbell() -> Result<()> {
        compare_mud_accept(
            "tests/mud_tests/Ring-Doorbell.json",
            "https://ringdoorbell.com/ringdoorbell",
            "tests/mud_tests/Ring-Doorbell-Test.json",
        )
    }

    #[test]
    fn test_example_ring_doorbell_wrong_expired() -> Result<()> {
        compare_mud_fail(
            "tests/mud_tests/Ring-Doorbell.json",
            "https://ringdoorbell.com/ringdoorbell",
            "tests/mud_tests/Ring-Doorbell-Test.json",
        )
    }

    #[test]
    fn test_example_august_doorbell() -> Result<()> {
        compare_mud_accept(
            "tests/mud_tests/August-Doorbell.json",
            "https://augustdoorbellcam.com/augustdoorbellcam",
            "tests/mud_tests/August-Doorbell-Test.json",
        )
    }

    #[test]
    fn test_example_august_doorbell_wrong_expired() -> Result<()> {
        compare_mud_fail(
            "tests/mud_tests/August-Doorbell.json",
            "https://augustdoorbellcam.com/augustdoorbellcam",
            "tests/mud_tests/August-Doorbell-Test.json",
        )
    }

    fn compare_mud(
        mud_profile_path: &str,
        mud_profile_url: &str,
        mud_profile_example_path: &str,
    ) -> Result<(MudData, String)> {
        let mut mud_data = String::new();
        let mut mud_data_test = String::new();

        let mut mud_profile = File::open(mud_profile_path)?;
        let mut mud_profile_test = File::open(mud_profile_example_path)?;

        mud_profile.read_to_string(&mut mud_data)?;
        mud_profile_test.read_to_string(&mut mud_data_test)?;

        let mud = parse_mud(mud_profile_url.to_string(), mud_data.as_str())?;
        Ok((mud, mud_data_test))
    }
    fn compare_mud_fail(mud_profile_path: &str, mud_profile_url: &str, mud_profile_example_path: &str) -> Result<()> {
        let mud_data = compare_mud(mud_profile_path, mud_profile_url, mud_profile_example_path)?;
        assert_ne!(
            serde_json::to_value(&mud_data.0)?,
            serde_json::from_str::<Value>(&mud_data.1)?
        );
        Ok(())
    }

    fn compare_mud_accept(mud_profile_path: &str, mud_profile_url: &str, mud_profile_example_path: &str) -> Result<()> {
        let mut data = compare_mud(mud_profile_path, mud_profile_url, mud_profile_example_path)?;
        let naive = NaiveDateTime::parse_from_str("2020-11-12T5:52:46", "%Y-%m-%dT%H:%M:%S")?;
        data.0.expiration = Utc.from_utc_datetime(&naive);
        assert_eq!(serde_json::to_value(&data.0)?, serde_json::from_str::<Value>(&data.1)?);
        Ok(())
    }
}
