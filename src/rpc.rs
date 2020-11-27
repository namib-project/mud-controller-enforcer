#![allow(clippy::large_enum_variant)]

use crate::{config_firewall::FirewallConfig, models::DhcpEvent};

#[tarpc::service]
pub trait RPC {
    async fn heartbeat(version: Option<String>) -> Option<FirewallConfig>;
    async fn dhcp_request(event: DhcpEvent);
}
