// Copyright 2020-2021,  Till Schnittka, Hannes Masuch
// SPDX-License-Identifier: MIT OR Apache-2.0

// watch has an event loop, so it needs to be async
#![allow(clippy::unused_async)]

use std::sync::Arc;
use tokio::sync::RwLock;

use namib_shared::flow_scope::{FlowData, FlowDataDirection, FlowDataTcp, FlowDataTransport, FlowDataUdp, LogGroup};

use pktparse::{ip, ipv4, ipv6, tcp, udp};

use nflog::{CopyMode, Queue};

use crate::{rpc::rpc_client, Enforcer};

pub async fn watch_ipv4(enforcer: Arc<RwLock<Enforcer>>) {
    debug!("Starting nflog watcher");

    let queue_ipv4 = Queue::open().unwrap();
    queue_ipv4.bind(libc::AF_INET).unwrap();

    let mut headers_from = queue_ipv4.bind_group(LogGroup::HeadersOnlyFromDevice as u16).unwrap();
    headers_from.set_mode(CopyMode::Packet, 0);
    headers_from.set_callback(generate_callback(
        enforcer.clone(),
        FlowDataDirection::FromDevice,
        false,
        false,
    ));

    let mut headers_to = queue_ipv4.bind_group(LogGroup::HeadersOnlyToDevice as u16).unwrap();
    headers_to.set_mode(CopyMode::Packet, 0);
    headers_to.set_callback(generate_callback(
        enforcer.clone(),
        FlowDataDirection::ToDevice,
        false,
        false,
    ));

    let mut full_from = queue_ipv4.bind_group(LogGroup::FullFromDevice as u16).unwrap();
    full_from.set_mode(CopyMode::Packet, 0);
    full_from.set_callback(generate_callback(
        enforcer.clone(),
        FlowDataDirection::FromDevice,
        true,
        false,
    ));

    let mut full_to = queue_ipv4.bind_group(LogGroup::FullToDevice as u16).unwrap();
    full_to.set_mode(CopyMode::Packet, 0);
    full_to.set_callback(generate_callback(
        enforcer.clone(),
        FlowDataDirection::ToDevice,
        true,
        false,
    ));

    let mut deny_to = queue_ipv4.bind_group(LogGroup::DenialsToDevice as u16).unwrap();
    deny_to.set_mode(CopyMode::Packet, 0);
    deny_to.set_callback(generate_callback(
        enforcer.clone(),
        FlowDataDirection::ToDevice,
        true,
        true,
    ));

    let mut deny_from = queue_ipv4.bind_group(LogGroup::DenialsFromDevice as u16).unwrap();
    deny_from.set_mode(CopyMode::Packet, 0);
    deny_from.set_callback(generate_callback(enforcer, FlowDataDirection::FromDevice, true, true));

    queue_ipv4.run_loop();
}

pub async fn watch_ipv6(enforcer: Arc<RwLock<Enforcer>>) {
    debug!("Starting nflog watcher");

    let queue_ipv6 = Queue::open().unwrap();
    queue_ipv6.bind(libc::AF_INET6).unwrap();

    let mut headers_from = queue_ipv6.bind_group(LogGroup::HeadersOnlyFromDevice as u16).unwrap();
    headers_from.set_mode(CopyMode::Packet, 0);
    headers_from.set_callback(generate_callback(
        enforcer.clone(),
        FlowDataDirection::FromDevice,
        false,
        false,
    ));

    let mut headers_to = queue_ipv6.bind_group(LogGroup::HeadersOnlyToDevice as u16).unwrap();
    headers_to.set_mode(CopyMode::Packet, 0);
    headers_to.set_callback(generate_callback(
        enforcer.clone(),
        FlowDataDirection::ToDevice,
        false,
        false,
    ));

    let mut full_from = queue_ipv6.bind_group(LogGroup::FullFromDevice as u16).unwrap();
    full_from.set_mode(CopyMode::Packet, 0);
    full_from.set_callback(generate_callback(
        enforcer.clone(),
        FlowDataDirection::FromDevice,
        true,
        false,
    ));

    let mut full_to = queue_ipv6.bind_group(LogGroup::FullToDevice as u16).unwrap();
    full_to.set_mode(CopyMode::Packet, 0);
    full_to.set_callback(generate_callback(
        enforcer.clone(),
        FlowDataDirection::ToDevice,
        true,
        false,
    ));

    let mut deny_to = queue_ipv6.bind_group(LogGroup::DenialsToDevice as u16).unwrap();
    deny_to.set_mode(CopyMode::Packet, 0);
    deny_to.set_callback(generate_callback(
        enforcer.clone(),
        FlowDataDirection::ToDevice,
        true,
        true,
    ));

    let mut deny_from = queue_ipv6.bind_group(LogGroup::DenialsFromDevice as u16).unwrap();
    deny_from.set_mode(CopyMode::Packet, 0);
    deny_from.set_callback(generate_callback(enforcer, FlowDataDirection::FromDevice, true, true));

    queue_ipv6.run_loop();
}

fn generate_callback(
    enforcer: Arc<RwLock<Enforcer>>,
    direction: FlowDataDirection,
    include_packet: bool,
    denied: bool,
) -> std::boxed::Box<dyn Fn(nflog::Message)> {
    std::boxed::Box::new(move |msg: nflog::Message| {
        {
            let payload_data = msg.get_payload();

            println!("packet ({})", payload_data.len());

            // if let Ok((remaining, eth_frame)) = ethernet::parse_ethernet_frame(payload_data) {
            let parsed = if let Ok((remaining, ipv4_packet)) = ipv4::parse_ipv4_header(payload_data) {
                Some((
                    std::net::IpAddr::V4(ipv4_packet.source_addr),
                    std::net::IpAddr::V4(ipv4_packet.dest_addr),
                    ipv4_packet.protocol,
                    ipv4_packet.length,
                    remaining,
                ))
            } else if let Ok((remaining, ipv6_packet)) = ipv6::parse_ipv6_header(payload_data) {
                Some((
                    std::net::IpAddr::V6(ipv6_packet.source_addr),
                    std::net::IpAddr::V6(ipv6_packet.dest_addr),
                    ipv6_packet.next_header,
                    ipv6_packet.length,
                    remaining,
                ))
            } else {
                None
            };

            if let Some((src_addr, dst_addr, protocol, length, remaining)) = parsed {
                let result = FlowData::new(
                    msg.get_timestamp().ok(),
                    src_addr,
                    dst_addr,
                    direction,
                    length,
                    match protocol {
                        ip::IPProtocol::TCP => {
                            if let Ok((_, tcp_header)) = tcp::parse_tcp_header(remaining) {
                                FlowDataTransport::Tcp(FlowDataTcp::new(
                                    match direction {
                                        FlowDataDirection::FromDevice => tcp_header.dest_port,
                                        FlowDataDirection::ToDevice => tcp_header.source_port,
                                    },
                                    match direction {
                                        FlowDataDirection::ToDevice => tcp_header.dest_port,
                                        FlowDataDirection::FromDevice => tcp_header.source_port,
                                    },
                                    tcp_header.flag_psh,
                                    tcp_header.flag_ece,
                                ))
                            } else {
                                FlowDataTransport::None
                            }
                        },
                        ip::IPProtocol::UDP => {
                            if let Ok((_, udp_header)) = udp::parse_udp_header(remaining) {
                                FlowDataTransport::Udp(FlowDataUdp::new(
                                    match direction {
                                        FlowDataDirection::FromDevice => udp_header.dest_port,
                                        FlowDataDirection::ToDevice => udp_header.source_port,
                                    },
                                    match direction {
                                        FlowDataDirection::ToDevice => udp_header.dest_port,
                                        FlowDataDirection::FromDevice => udp_header.source_port,
                                    },
                                ))
                            } else {
                                FlowDataTransport::None
                            }
                        },
                        _ => FlowDataTransport::None,
                    },
                    if include_packet {
                        Some(payload_data.into())
                    } else {
                        None
                    },
                    denied,
                );
                let _send = futures::executor::block_on(
                    futures::executor::block_on(enforcer.read())
                        .client
                        .send_scope_results(rpc_client::current_rpc_context(), vec![result]),
                );
            }
        }
    })
}
