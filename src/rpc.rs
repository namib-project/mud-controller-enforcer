use crate::models::DhcpEvent;

#[tarpc::service]
pub trait RPC {
    async fn heartbeat();
    async fn dhcp_request(event: DhcpEvent);
}
