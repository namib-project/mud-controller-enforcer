#![warn(clippy::all, clippy::style, clippy::pedantic)]
#![allow(dead_code, clippy::module_name_repetitions)]

#[macro_use]
extern crate log;

use std::sync::Arc;

use dotenv::dotenv;
use tokio::{fs, fs::OpenOptions, sync::Mutex};

use crate::services::firewall_service::FirewallService;
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

    info!(
        "Starting in {} mode",
        if services::is_system_mode() { "SYSTEM" } else { "USER" }
    );
    if !services::is_system_mode() {
        fs::create_dir_all("config").await?;
        OpenOptions::new()
            .write(true)
            .create(true)
            .open("config/firewall")
            .await?;
    }

    let enforcer_state = Arc::new(services::state::EnforcerState::new());
    info!("Trying to find & connect to NAMIB Controller");

    let client: Arc<Mutex<RPCClient>> = Arc::new(Mutex::new(rpc::rpc_client::run().await?));
    info!("Connected to NAMIB Controller RPC server");

    let mut dns_service = services::dns::DnsService::new().unwrap();

    let watcher = dns_service.create_watcher();
    let fw_service = Arc::new(FirewallService::new(enforcer_state.clone(), watcher));

    let heartbeat_task = rpc::rpc_client::heartbeat(enforcer_state.clone(), client.clone(), fw_service.clone());

    let dhcp_event_task = dhcp::dhcp_event_listener::listen_for_dhcp_events(client);

    let dns_task = tokio::spawn(async move {
        dns_service.auto_refresher_task().await;
    });

    let firewall_task = tokio::spawn(async move {
        fw_service.firewall_change_watcher().await;
    });

    tokio::join!(heartbeat_task, dhcp_event_task, dns_task, firewall_task);
    Ok(())
}
