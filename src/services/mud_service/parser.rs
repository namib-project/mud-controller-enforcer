use std::{clone::Clone, net::IpAddr, str::FromStr};

use chrono::{Duration, Utc};
use snafu::ensure;

use crate::{
    error::{MudError, Result},
    models::{Ace, AceAction, AceMatches, AcePort, AceProtocol, Acl, AclDirection, AclType, MudData},
};

use super::json_models;

// inspired by https://github.com/CiscoDevNet/MUD-Manager by Cisco
pub fn parse_mud(url: String, json: &str) -> Result<MudData> {
    let mud_json: json_models::MudJson = serde_json::from_str(json)?;

    let mud_data = &mud_json.mud;
    if mud_data.mud_version != 1 {
        MudError {
            message: String::from("Unsupported MUD Version"),
        }
        .fail()?;
    }
    let cachevalidity = mud_data.cache_validity.unwrap_or(48);
    ensure!(
        cachevalidity >= 1 && cachevalidity <= 168,
        MudError {
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
                    if let Some(udp) = &aceitem.matches.udp {
                        protocol = Some(AceProtocol::UDP);
                        source_port = udp.source_port.as_ref().and_then(|p| parse_mud_port(p).ok());
                        destination_port = udp.destination_port.as_ref().and_then(|p| parse_mud_port(p).ok());
                    } else if let Some(tcp) = &aceitem.matches.tcp {
                        protocol = Some(AceProtocol::TCP);
                        if let Some(dir) = &tcp.direction_initiated {
                            direction_initiated = Some(match dir.as_str() {
                                "from-device" => AclDirection::FromDevice,
                                "to-device" => AclDirection::ToDevice,
                                _ => MudError {
                                    message: String::from("Invalid direction"),
                                }
                                .fail()?,
                            });
                        }

                        source_port = tcp.source_port.as_ref().and_then(|p| parse_mud_port(p).ok());
                        destination_port = tcp.destination_port.as_ref().and_then(|p| parse_mud_port(p).ok());
                    }
                    if let Some(ipv6) = &aceitem.matches.ipv6 {
                        if acl_type != AclType::IPV6 {
                            MudError {
                                message: String::from("IPv6 ACE in IPv4 ACL"),
                            }
                            .fail()?
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
                            MudError {
                                message: String::from("IPv4 ACE in IPv6 ACL"),
                            }
                            .fail()?
                        }
                        protocol = ipv4.protocol.map(AceProtocol::Protocol);
                        address_mask = ipv4
                            .source_ipv4_network
                            .as_ref()
                            .or_else(|| ipv4.destination_ipv4_network.as_ref())
                            .and_then(|srcip| IpAddr::from_str(srcip.as_str()).ok());
                        dnsname = ipv4.dst_dnsname.clone().or_else(|| ipv4.src_dnsname.clone());
                    }
                    if let Some(_mud) = &aceitem.matches.mud {
                        // see https://github.com/CiscoDevNet/MUD-Manager/blob/master/src/mud_manager.c#L1472
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
                        },
                    })
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
            MudError {
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
                MudError {
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
                MudError {
                    message: String::from("No operator for port range")
                }
            );
            Ok(AcePort::Range(*lower_port, *upper_port))
        },
        _ => MudError {
            message: String::from("Invalid port definition"),
        }
        .fail()?,
    }
}
