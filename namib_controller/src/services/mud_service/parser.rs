// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::clone::Clone;
use std::convert::TryFrom;

use chrono::{Duration, Utc};
use snafu::ensure;

use super::json_models;
use crate::error::Error;
use crate::models::{
    IcmpMatches, IcmpRestOfHeader, Ipv4HeaderFlags, Ipv4Matches, Ipv6Matches, L3Matches, L4Matches,
    MudAclMatchesAugmentation, SourceDest, TcpHeaderFlags, TcpMatches, TcpOptions, UdpMatches,
    ICMP_REST_OF_HEADER_BYTES,
};
use crate::{
    error,
    error::Result,
    models::{Ace, AceAction, AceMatches, AcePort, AceProtocol, Acl, AclDirection, AclType, MudData},
};

impl TryFrom<&json_models::Bits> for TcpHeaderFlags {
    type Error = Error;

    fn try_from(value: &json_models::Bits) -> Result<Self> {
        // NOTE(ja_he): technically, the YANG type mandates appearance of flags _in order_.
        //              IMO this leniency is fine. Could think about being strict regarding unknown
        //              flag names or flag uniqueness, but we're not trying to be a MUD linter.
        let flag_strings: Vec<&str> = value.split(' ').collect();
        Ok(TcpHeaderFlags {
            cwr: Some(flag_strings.contains(&"cwr")),
            ece: Some(flag_strings.contains(&"ece")),
            urg: Some(flag_strings.contains(&"urg")),
            ack: Some(flag_strings.contains(&"ack")),
            psh: Some(flag_strings.contains(&"psh")),
            rst: Some(flag_strings.contains(&"rst")),
            syn: Some(flag_strings.contains(&"syn")),
            fin: Some(flag_strings.contains(&"fin")),
        })
    }
}

impl TryFrom<&json_models::Bits> for Ipv4HeaderFlags {
    type Error = Error;

    fn try_from(value: &json_models::Bits) -> Result<Self> {
        // NOTE(ja_he): technically, the YANG type mandates appearance of flags _in order_.
        //              IMO this leniency is fine. Could think about being strict regarding unknown
        //              flag names or flag uniqueness, but we're not trying to be a MUD linter.
        let flag_strings: Vec<&str> = value.split(' ').collect();
        Ok(Self {
            reserved: Some(flag_strings.contains(&"reserved")),
            fragment: Some(flag_strings.contains(&"fragment")),
            more: Some(flag_strings.contains(&"more")),
        })
    }
}

impl TryFrom<&json_models::Binary> for TcpOptions {
    type Error = Error;

    fn try_from(value: &json_models::Binary) -> Result<Self> {
        let bytes: Vec<u8> = base64::decode(value).map_err(|_| Error::MudError {
            message: format!("base64-decoding error for TCP options value '{}'", value),
            // HACK(ja_he): I don't know how to use `error::MudError` as below, there's some snafu
            //              magic going on and I can't figure out how to wrangle the types, because
            //              to me it seems like it should be the right type but the type checker
            //              complains.
            backtrace: snafu::GenerateBacktrace::generate(),
        })?;

        // TODO(ja_he): further parsing probably sensible, type would likely have to be changed
        Ok(Self {
            kind: bytes[0],
            length: if bytes.len() >= 2 { Some(bytes[1]) } else { None },
            data: bytes[2..].to_vec(),
        })
    }
}

impl TryFrom<&json_models::Tcp> for TcpMatches {
    type Error = Error;

    fn try_from(value: &json_models::Tcp) -> Result<Self> {
        Ok(Self {
            ports: SourceDest::new(
                &value.source_port.as_ref().map(parse_mud_port).transpose()?,
                &value.destination_port.as_ref().map(parse_mud_port).transpose()?,
            ),
            sequence_number: value.sequence_number,
            acknowledgement_number: value.acknowledgement_number,
            data_offset: value.data_offset,
            reserved: value.reserved,
            flags: value.flags.as_ref().map(TcpHeaderFlags::try_from).transpose()?,
            window_size: value.window_size,
            urgent_pointer: value.urgent_pointer,
            options: value.options.as_ref().map(TcpOptions::try_from).transpose()?,
            direction_initiated: match &value.direction_initiated.as_deref() {
                None => None,
                Some("from-device") => Some(AclDirection::FromDevice),
                Some("to-device") => Some(AclDirection::ToDevice),
                Some(other) => error::MudError {
                    message: format!("Invalid direction '{}'", other),
                }
                .fail()?,
            },
        })
    }
}

impl TryFrom<&json_models::Udp> for UdpMatches {
    type Error = Error;

    fn try_from(value: &json_models::Udp) -> Result<Self> {
        Ok(Self {
            length: value.length,
            ports: SourceDest::new(
                &value.source_port.as_ref().map(parse_mud_port).transpose()?,
                &value.destination_port.as_ref().map(parse_mud_port).transpose()?,
            ),
        })
    }
}

impl TryFrom<&json_models::Icmp> for IcmpMatches {
    type Error = Error;

    fn try_from(value: &json_models::Icmp) -> Result<Self> {
        let rest_of_header: Option<IcmpRestOfHeader> = {
            if let Some(binary) = &value.rest_of_header {
                let bytes = base64::decode(binary).map_err(|_| Error::MudError {
                    message: format!("base64-decoding error for ICMP rest-of-header '{}'", binary),
                    backtrace: snafu::GenerateBacktrace::generate(),
                })?;

                if bytes.len() == ICMP_REST_OF_HEADER_BYTES {
                    // STYLE(ja_he):
                    //   I manually assign the 4 bytes because the intuitive `try_into`-attempt
                    //   gives me trouble with multiple implementations.
                    //   Additionally, the whole assignment of `rest_of_header` is very
                    //   wordy due to the fact that I can't get anything less verbose past the type
                    //   checker (surely my failing).
                    Ok(Some([bytes[0], bytes[1], bytes[2], bytes[3]]))
                } else {
                    Err(Error::MudError {
                        message: format!(
                            "rest of header binary gives {} bytes instead of {}",
                            bytes.len(),
                            ICMP_REST_OF_HEADER_BYTES
                        ),
                        backtrace: snafu::GenerateBacktrace::generate(),
                    })
                }
            } else {
                Ok(None)
            }
        }?;

        Ok(Self {
            icmp_type: value.icmp_type,
            icmp_code: value.code,
            rest_of_header,
        })
    }
}

impl TryFrom<&json_models::Ipv4> for Ipv4Matches {
    type Error = Error;

    fn try_from(value: &json_models::Ipv4) -> Result<Self> {
        Ok(Self {
            dscp: value.dscp,
            ecn: value.ecn,
            length: value.length,
            ttl: value.ttl,
            protocol: value.protocol.map(|p| AceProtocol::Protocol(p.into())),
            ihl: value.ihl,
            flags: value.flags.as_ref().map(Ipv4HeaderFlags::try_from).transpose()?,
            offset: value.offset,
            identification: value.identification,
            networks: SourceDest::new(&value.source_ipv4_network, &value.destination_ipv4_network),
            dnsnames: SourceDest::new(&value.src_dnsname, &value.dst_dnsname),
        })
    }
}

impl TryFrom<&json_models::Ipv6> for Ipv6Matches {
    type Error = Error;

    fn try_from(value: &json_models::Ipv6) -> Result<Self> {
        Ok(Self {
            dscp: value.dscp,
            ecn: value.ecn,
            length: value.length,
            ttl: value.ttl,
            protocol: value.protocol.map(AceProtocol::Protocol),
            flow_label: value.flow_label,
            networks: SourceDest::new(&value.source_ipv6_network, &value.destination_ipv6_network),
            dnsnames: SourceDest::new(&value.src_dnsname, &value.dst_dnsname),
        })
    }
}

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
        match &mud_json
            .acls
            .acl
            .iter()
            .find(|aclitem| aclitem.name == access_list.name)
        {
            Some(aclitem) => {
                let mut ace: Vec<Ace> = Vec::new();
                let acl_type = if aclitem.type_field == "ipv4-acl-type" {
                    AclType::IPV4
                } else {
                    AclType::IPV6
                };
                for aceitem in &aclitem.aces.ace {
                    let mut l3 = None;
                    let mut l4 = None;
                    let mut matches_augmentation = None;

                    let mut l4_protocol_for_matching = None;

                    match (&aceitem.matches.tcp, &aceitem.matches.udp, &aceitem.matches.icmp) {
                        (None, None, None) => {},
                        (Some(tcp), None, None) => {
                            l4_protocol_for_matching = Some(AceProtocol::Tcp);
                            l4 = Some(L4Matches::Tcp(TcpMatches::try_from(tcp)?));
                        },
                        (None, Some(udp), None) => {
                            l4_protocol_for_matching = Some(AceProtocol::Udp);
                            l4 = Some(L4Matches::Udp(UdpMatches::try_from(udp)?));
                        },
                        (None, None, Some(icmp)) => {
                            l4_protocol_for_matching = Some(AceProtocol::Icmp);
                            l4 = Some(L4Matches::Icmp(IcmpMatches::try_from(icmp)?));
                        },
                        _ => error::MudError {
                            message: String::from("Multiple L4 matches specified, which does not conform to RFC8519"),
                        }
                        .fail()?,
                    }

                    match (&aceitem.matches.ipv4, &aceitem.matches.ipv6) {
                        (None, None) => {},
                        (Some(ipv4), None) => {
                            if acl_type != AclType::IPV4 {
                                error::MudError {
                                    message: String::from("IPv4 ACE in IPv6 ACL"),
                                }
                                .fail()?;
                            }
                            let ip_header_protocol = &ipv4.protocol.map(|p| AceProtocol::from(p as u8));
                            if let (Some(matching_proto), Some(header_proto)) =
                                (l4_protocol_for_matching, ip_header_protocol)
                            {
                                if matching_proto != *header_proto {
                                    error::MudError {
                                        message: format!(
                                            "IPv4 header protocol and L4 protocol used for matching differ: {} != {}",
                                            matching_proto, header_proto
                                        ),
                                    }
                                    .fail()?;
                                }
                            }
                            l3 = Some(L3Matches::Ipv4(Ipv4Matches::try_from(ipv4)?));
                        },
                        (None, Some(ipv6)) => {
                            if acl_type != AclType::IPV6 {
                                error::MudError {
                                    message: String::from("IPv6 ACE in IPv4 ACL"),
                                }
                                .fail()?;
                            }
                            let ip_header_protocol = &ipv6.protocol.map(AceProtocol::Protocol);
                            if let (Some(matching_proto), Some(header_proto)) =
                                (l4_protocol_for_matching, ip_header_protocol)
                            {
                                if matching_proto != *header_proto {
                                    error::MudError {
                                        message: format!(
                                            "IPv6 header protocol and L4 protocol used for matching differ: {} != {}",
                                            matching_proto, header_proto
                                        ),
                                    }
                                    .fail()?;
                                }
                            }
                            l3 = Some(L3Matches::Ipv6(Ipv6Matches::try_from(ipv6)?));
                        },
                        _ => {
                            error::MudError {
                                message: String::from(
                                    "Multiple L3 matches specified, which does not conform to RFC8519",
                                ),
                            }
                            .fail()?;
                        },
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
                            l3,
                            l4,
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
            },
            None => {
                error::MudError {
                    message: String::from("MUD-File has dangling ACL policy"),
                }
                .fail()?;
            },
        }
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

    use super::*;

    #[test]
    fn test_trivial_example() -> Result<()> {
        const URL: &str = "https://lighting.example.com/lightbulb2000";
        let mut mud_data = String::new();
        let mut mud_profile = File::open("tests/mud_tests/MUD-Profile-example.json")?;
        mud_profile.read_to_string(&mut mud_data)?;

        let mud = parse_mud(URL.to_string(), mud_data.as_str())?;

        let matches = AceMatches {
            l3: None,
            l4: None,
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
    fn test_dangling_detected() {
        // no dangling policy
        {
            let data = r#"{
                            "ietf-mud:mud" : {
                              "mud-version" : 1,
                              "mud-url" : "https://manufacturer.com/thing",
                              "last-update" : "2018-09-16T13:53:04.908+10:00",
                              "cache-validity" : 100,
                              "is-supported" : true,
                              "systeminfo" : "amazonEcho",
                              "from-device-policy" : { "access-lists" : { "access-list" : [ { "name" : "a" } ] } },
                              "to-device-policy" :   { "access-lists" : { "access-list" : [ { "name" : "x" } ] } }
                            },
                            "ietf-access-control-list:access-lists" : {
                              "acl" : [ {
                                "name" : "a",
                                "type" : "ipv4-acl-type",
                                "aces" : {
                                  "ace" : [  ]
                                }
                              }, {
                                "name" : "x",
                                "type" : "ipv4-acl-type",
                                "aces" : {
                                  "ace" : [  ]
                                }
                              } ]
                            }
                          }"#;

            if let Err(e) = parse_mud("https://manufacturer.com/thing".to_string(), data) {
                panic!("parsing mostly empty but valid MUD JSON returned an error: {}", e);
            }
        }

        // dangling from-device-policy "b"
        {
            let data = r#"{
                            "ietf-mud:mud" : {
                              "mud-version" : 1,
                              "mud-url" : "https://manufacturer.com/thing",
                              "last-update" : "2018-09-16T13:53:04.908+10:00",
                              "cache-validity" : 100,
                              "is-supported" : true,
                              "systeminfo" : "amazonEcho",
                              "from-device-policy" : { "access-lists" : { "access-list" : [ { "name" : "a", "b" } ] } },
                              "to-device-policy" :   { "access-lists" : { "access-list" : [ { "name" : "x"      } ] } }
                            },
                            "ietf-access-control-list:access-lists" : {
                              "acl" : [ {
                                "name" : "a",
                                "type" : "ipv4-acl-type",
                                "aces" : {
                                  "ace" : [  ]
                                }
                              }, {
                                "name" : "x",
                                "type" : "ipv4-acl-type",
                                "aces" : {
                                  "ace" : [  ]
                                }
                              } ]
                            }
                          }"#;

            assert!(
                !parse_mud("https://manufacturer.com/thing".to_string(), data).is_ok(),
                "parsing MUD JSON with dangling policy 'b' SHOULD return an error, BUT does not"
            );
        }

        // dangling to-device-policy "y"
        {
            let data = r#"{
                            "ietf-mud:mud" : {
                              "mud-version" : 1,
                              "mud-url" : "https://manufacturer.com/thing",
                              "last-update" : "2018-09-16T13:53:04.908+10:00",
                              "cache-validity" : 100,
                              "is-supported" : true,
                              "systeminfo" : "amazonEcho",
                              "from-device-policy" : { "access-lists" : { "access-list" : [ { "name" : "a"      } ] } },
                              "to-device-policy" :   { "access-lists" : { "access-list" : [ { "name" : "x", "y" } ] } }
                            },
                            "ietf-access-control-list:access-lists" : {
                              "acl" : [ {
                                "name" : "a",
                                "type" : "ipv4-acl-type",
                                "aces" : {
                                  "ace" : [  ]
                                }
                              }, {
                                "name" : "x",
                                "type" : "ipv4-acl-type",
                                "aces" : {
                                  "ace" : [  ]
                                }
                              } ]
                            }
                          }"#;

            assert!(
                !parse_mud("https://manufacturer.com/thing".to_string(), data).is_ok(),
                "parsing MUD JSON with dangling policy 'y' SHOULD return an error, BUT does not"
            );
        }
    }

    #[test]
    fn test_tcp_header_flags() -> Result<()> {
        {
            let bits: json_models::Bits = String::from("");
            let header_flags: TcpHeaderFlags = TcpHeaderFlags::try_from(&bits)?;
            assert_eq!(
                header_flags,
                TcpHeaderFlags {
                    cwr: Some(false),
                    ece: Some(false),
                    urg: Some(false),
                    ack: Some(false),
                    psh: Some(false),
                    rst: Some(false),
                    syn: Some(false),
                    fin: Some(false)
                }
            );
        }

        {
            let bits: json_models::Bits = String::from("ece");
            let header_flags: TcpHeaderFlags = TcpHeaderFlags::try_from(&bits)?;
            assert_eq!(
                header_flags,
                TcpHeaderFlags {
                    cwr: Some(false),
                    ece: Some(true),
                    urg: Some(false),
                    ack: Some(false),
                    psh: Some(false),
                    rst: Some(false),
                    syn: Some(false),
                    fin: Some(false)
                }
            );
        }

        {
            let bits: json_models::Bits = String::from("cwr ack fin");
            let header_flags: TcpHeaderFlags = TcpHeaderFlags::try_from(&bits)?;
            assert_eq!(
                header_flags,
                TcpHeaderFlags {
                    cwr: Some(true),
                    ece: Some(false),
                    urg: Some(false),
                    ack: Some(true),
                    psh: Some(false),
                    rst: Some(false),
                    syn: Some(false),
                    fin: Some(true)
                }
            );
        }

        {
            // NOTE(ja_he): I claim we want to be permissive in this case and simply ignore
            //              extraneous flags.
            let bits: json_models::Bits = String::from("this test is fun");
            let header_flags: TcpHeaderFlags = TcpHeaderFlags::try_from(&bits)?;
            assert_eq!(
                header_flags,
                TcpHeaderFlags {
                    cwr: Some(false),
                    ece: Some(false),
                    urg: Some(false),
                    ack: Some(false),
                    psh: Some(false),
                    rst: Some(false),
                    syn: Some(false),
                    fin: Some(false)
                }
            );
        }

        {
            let data = r#"{
                            "ietf-mud:mud" : {
                              "mud-version" : 1,
                              "mud-url" : "https://manufacturer.com/thing",
                              "last-update" : "2018-09-16T13:53:04.908+10:00",
                              "cache-validity" : 100,
                              "is-supported" : true,
                              "from-device-policy" : { "access-lists" : { "access-list" : [ { "name" : "a" } ] } },
                              "to-device-policy" :   { "access-lists" : { "access-list" : [ { "name" : "x" } ] } }
                            },
                            "ietf-access-control-list:access-lists" : {
                              "acl" : [ {
                                "name" : "a",
                                "type" : "ipv4-acl-type",
                                "aces" : {
                                  "ace" : [ {
                                    "name": "cool-ace",
                                    "matches": {
                                      "tcp": { "flags": "syn" }
                                    },
                                    "actions": { "forwarding": "accept" }
                                  } ]
                                }
                              }, {
                                "name" : "x",
                                "type" : "ipv4-acl-type",
                                "aces" : {
                                  "ace" : [  ]
                                }
                              } ]
                            }
                          }"#;

            let mud: MudData = parse_mud("https://manufacturer.com/thing".to_string(), data)?;
            assert_eq!(
                mud,
                MudData {
                    url: "https://manufacturer.com/thing".to_string(),
                    masa_url: None,
                    last_update: "2018-09-16T13:53:04.908+10:00".to_string(),
                    systeminfo: None,
                    mfg_name: None,
                    model_name: None,
                    documentation: None,
                    expiration: mud.expiration, // :^)
                    acllist: vec![
                        Acl {
                            name: "a".to_string(),
                            packet_direction: AclDirection::FromDevice,
                            acl_type: AclType::IPV4,
                            ace: vec![Ace {
                                name: "cool-ace".to_string(),
                                action: AceAction::Accept,
                                matches: AceMatches {
                                    l3: None,
                                    l4: Some(L4Matches::Tcp(TcpMatches {
                                        sequence_number: None,
                                        acknowledgement_number: None,
                                        data_offset: None,
                                        reserved: None,
                                        flags: Some(TcpHeaderFlags {
                                            cwr: Some(false),
                                            ece: Some(false),
                                            urg: Some(false),
                                            ack: Some(false),
                                            psh: Some(false),
                                            rst: Some(false),
                                            syn: Some(true),
                                            fin: Some(false),
                                        }),
                                        window_size: None,
                                        urgent_pointer: None,
                                        options: None,
                                        ports: SourceDest { src: None, dst: None },
                                        direction_initiated: None,
                                    })),
                                    matches_augmentation: None,
                                }
                            },],
                        },
                        Acl {
                            name: "x".to_string(),
                            packet_direction: AclDirection::ToDevice,
                            acl_type: AclType::IPV4,
                            ace: vec![],
                        }
                    ],
                    acl_override: vec![],
                },
            );
        }

        Ok(())
    }
}
