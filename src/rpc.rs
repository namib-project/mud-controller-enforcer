use crate::models::DHCPRequestData;

#[tarpc::service]
pub trait RPC {
    async fn heartbeat();
    async fn dhcp_request(message: DHCPRequestData);
}
