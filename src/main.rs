#![warn(clippy::all, clippy::style, clippy::pedantic)]
#![allow(dead_code, clippy::module_name_repetitions)]

#[macro_use]
extern crate log;

use std::sync::Arc;

use dotenv::dotenv;
use namib_shared::rpc::RPCClient;
use tokio::sync::Mutex;

use error::Result;

mod dhcp;
mod error;
mod rpc;
mod services;
mod uci;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    dotenv()?;
    env_logger::init();

    let client: Arc<Mutex<RPCClient>> = Arc::new(Mutex::new(rpc::rpc_client::run().await?));
    info!("Connected to RPC server");

    let heartbeat_task = rpc::rpc_client::heartbeat(client.clone());

    let dhcp_event_task = dhcp::dhcp_event_listener::listen_for_dhcp_events(client);

    tokio::join!(heartbeat_task, dhcp_event_task);
    Ok(())
}
