#![warn(clippy::all, clippy::style, clippy::pedantic)]
#![allow(dead_code, clippy::module_name_repetitions)]

#[macro_use]
extern crate log;

use std::sync::Arc;

use dotenv::dotenv;
use tokio::{fs, fs::OpenOptions, sync::Mutex};

use error::Result;
use namib_shared::rpc::RPCClient;

mod dhcp;
mod error;
mod rpc;
mod services;
mod uci;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    dotenv().ok();
    env_logger::init();

    info!("Starting in {} mode", if services::is_system_mode() { "SYSTEM" } else { "USER" });
    if !services::is_system_mode() {
        fs::create_dir_all("config").await?;
        OpenOptions::new().create(true).open("config/firewall").await?;
    }

    let client: Arc<Mutex<RPCClient>> = Arc::new(Mutex::new(rpc::rpc_client::run().await?));
    info!("Connected to RPC server");

    let heartbeat_task = rpc::rpc_client::heartbeat(client.clone());

    let dhcp_event_task = dhcp::dhcp_event_listener::listen_for_dhcp_events(client);

    tokio::join!(heartbeat_task, dhcp_event_task);
    Ok(())
}
