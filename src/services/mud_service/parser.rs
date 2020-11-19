use std::clone::Clone;
use std::net::IpAddr;
use std::str::FromStr;

use chrono::{Duration, Local};
use snafu::ensure;

use crate::error::*;
use crate::models::mud_models::*;

use super::json_models;

// inspired by https://github.com/CiscoDevNet/MUD-Manager by Cisco
pub fn parse_mud(url: String, json: String) -> Result<MUDData> {
    let mudjson: json_models::MudJson = serde_json::from_str(json.as_str())?;

    let mud_json = &mudjson.mud;
    if mud_json.mud_version != 1 {
        MudError {
            message: String::from("Unsupported MUD Version"),
        }
        .fail()?;
    }
    let cachevalidity = mud_json.cache_validity.unwrap_or(48);
    ensure!(
        cachevalidity >= 1 && cachevalidity <= 168,
        MudError {
            message: String::from("MUD-File has invalid 'cache-validity'")
        }
    );
    let exptime = Local::now() + Duration::hours(cachevalidity);

    // parse masa
    let mut masa_uri = None;
    if let Some(extensions) = &mud_json.extensions {
        for ext in extensions {
            if ext == "masa" {
                if let Some(masa) = &mud_json.masa_server {
                    masa_uri = Some(masa.clone());
                }
            }
        }
    }
    let mut acllist = Vec::new();
    parse_device_policy(
        &mud_json.from_device_policy,
        &mudjson,
        &mut acllist,
        ACLDirection::FromDevice,
    )?;
    parse_device_policy(
        &mud_json.to_device_policy,
        &mudjson,
        &mut acllist,
        ACLDirection::ToDevice,
    )?;

    let data = MUDData {
        url,
        masa_url: masa_uri,
        last_update: mud_json.last_update.clone(),
        systeminfo: mud_json.systeminfo.clone(),
        mfg_name: mud_json.mfg_name.clone(),
        model_name: mud_json.model_name.clone(),
        documentation: mud_json.documentation.clone(),
        expiration: exptime,
        acllist,
    };
    info!(
        "MUD URI <{}> Last Update <{}> System Info <{}> Cache-Validity <{}> MASA <{:?}> Expiration <{}>",
        data.url,
        data.last_update,
        data.systeminfo,
        cachevalidity,
        data.masa_url,
        exptime
    );

    Ok(data)
}

fn parse_device_policy(
    policy: &json_models::Policy,
    mud_json: &json_models::MudJson,
    acllist: &mut Vec<ACL>,
    dir: ACLDirection,
) -> Result<()> {
    for access_list in &policy.access_lists.access_list {
        let mut found = false;
        for aclitem in &mud_json.acls.acl {
            if aclitem.name == access_list.name {
                let mut ace: Vec<ACE> = Vec::new();
                let acl_type = if aclitem.type_field == "ipv4-acl-type" {
                    ACLType::IPV4
                } else {
                    ACLType::IPV6
                };
                for aceitem in &aclitem.aces.ace {
                    let mut protocol = None;
                    let mut direction_initiated = None;
                    let mut address_mask = None;
                    let mut dnsname = None;
                    let mut source_port = None;
                    let mut destination_port = None;
                    if let Some(udp) = &aceitem.matches.udp {
                        protocol = Some(ACEProtocol::UDP);
                        source_port = Some(parse_mud_port(&udp.source_port)?);
                        destination_port = Some(parse_mud_port(&udp.destination_port)?);
                    } else if let Some(tcp) = &aceitem.matches.tcp {
                        protocol = Some(ACEProtocol::TCP);
                        if let Some(dir) = &tcp.direction_initiated {
                            direction_initiated = Some(match dir.as_str() {
                                "from-device" => ACLDirection::FromDevice,
                                "to-device" => ACLDirection::ToDevice,
                                _ => MudError {
                                    message: String::from("Invalid direction"),
                                }
                                .fail()?,
                            });
                        }

                        source_port = Some(parse_mud_port(&tcp.source_port)?);
                        destination_port = Some(parse_mud_port(&tcp.destination_port)?);
                    }
                    if let Some(ipv6) = &aceitem.matches.ipv6 {
                        if acl_type != ACLType::IPV6 {
                            MudError {
                                message: String::from("IPv6 ACE in IPv4 ACL"),
                            }
                            .fail()?
                        }
                        protocol = ipv6.protocol.map(|p| ACEProtocol::Protocol(p as u32));
                        address_mask = {
                            if let Some(srcip) = &ipv6.source_ipv6_network {
                                IpAddr::from_str(srcip.as_str()).ok()
                            } else if let Some(dstip) = &ipv6.destination_ipv6_network {
                                IpAddr::from_str(dstip.as_str()).ok()
                            } else {
                                None
                            }
                        };
                        dnsname = ipv6
                            .dst_dnsname
                            .clone()
                            .or_else(|| ipv6.src_dnsname.clone());
                    } else if let Some(ipv4) = &aceitem.matches.ipv4 {
                        if acl_type != ACLType::IPV4 {
                            MudError {
                                message: String::from("IPv4 ACE in IPv6 ACL"),
                            }
                            .fail()?
                        }
                        protocol = ipv4.protocol.map(|p| ACEProtocol::Protocol(p as u32));
                        address_mask = {
                            if let Some(srcip) = &ipv4.source_ipv4_network {
                                IpAddr::from_str(srcip.as_str()).ok()
                            } else if let Some(dstip) = &ipv4.destination_ipv4_network {
                                IpAddr::from_str(dstip.as_str()).ok()
                            } else {
                                None
                            }
                        };
                        dnsname = ipv4
                            .dst_dnsname
                            .clone()
                            .or_else(|| ipv4.src_dnsname.clone());
                    }
                    if let Some(_mud) = &aceitem.matches.mud {
                        // see https://github.com/CiscoDevNet/MUD-Manager/blob/master/src/mud_manager.c#L1472
                    }
                    ace.push(ACE {
                        name: aceitem.name.clone(),
                        action: if aceitem.actions.forwarding == "accept" {
                            ACEAction::Accept
                        } else {
                            ACEAction::Deny
                        },
                        matches: ACEMatches {
                            protocol,
                            direction_initiated,
                            address_mask,
                            dnsname,
                            source_port,
                            destination_port,
                        },
                    })
                }

                acllist.push(ACL {
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

fn parse_mud_port(port: &json_models::Port) -> Result<ACEPort> {
    match port {
        json_models::Port { port: Some(p), .. } => {
            ensure!(
                port.operator == Some(String::from("eq")),
                MudError {
                    message: String::from("Only 'eq' operator is supported")
                }
            );
            Ok(ACEPort::Single(p.clone() as u32))
        }
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
            Ok(ACEPort::Range(
                lower_port.clone() as u32,
                upper_port.clone() as u32,
            ))
        }
        _ => MudError {
            message: String::from("Invalid port definition"),
        }
        .fail()?,
    }
}
