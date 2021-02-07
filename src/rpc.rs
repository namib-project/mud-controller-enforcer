#![allow(clippy::large_enum_variant)]

use crate::{firewall_config::FirewallConfig, models::DhcpEvent};

#[tarpc::service]
pub trait RPC {
    async fn heartbeat(version: Option<String>) -> Option<FirewallConfig>;
    async fn dhcp_request(event: DhcpEvent);
    async fn send_logs(logs: Vec<String>);
}
