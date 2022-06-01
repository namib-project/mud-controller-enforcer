// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::large_enum_variant)]

use crate::{flow_scope::FlowData, models::DhcpEvent, EnforcerConfig};
use chrono::NaiveDateTime;

/// This is the interface for communication between enforcer & controller
///
/// All types implementing `serde::Serializable` can be transferred,
/// however function calls can only be made by the enforcer.
#[tarpc::service]
pub trait NamibRpc {
    async fn heartbeat(version: Option<String>, next_expiration: Option<NaiveDateTime>) -> Option<EnforcerConfig>;
    async fn dhcp_request(event: DhcpEvent);
    async fn send_logs(logs: Vec<String>);
    async fn send_scope_results(results: Vec<FlowData>);
}
