use crate::config_firewall::FirewallConfig;
use crate::models::DHCPRequestData;

#[tarpc::service]
pub trait RPC {
    async fn heartbeat(version: Option<String>) -> Option<FirewallConfig>;
    async fn dhcp_request(message: DHCPRequestData);
}
