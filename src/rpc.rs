use tarpc;
use serde::{Deserialize, Serialize};

#[tarpc::service]
pub trait RPC {
    async fn heartbeat();
}