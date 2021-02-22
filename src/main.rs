#![warn(clippy::all, clippy::style, clippy::pedantic)]
#![allow(dead_code, clippy::module_name_repetitions)]

#[macro_use]
extern crate log;

use std::sync::Arc;

use dotenv::dotenv;
use tokio::{fs, fs::OpenOptions, sync::Mutex};

use crate::{rpc::rpc_client::current_rpc_context, services::firewall_service::FirewallService};
use error::Result;
use namib_shared::{firewall_config::EnforcerConfig, rpc::RPCClient};
use std::thread;
use tokio::sync::RwLock;

mod dhcp;
mod error;
mod rpc;
mod services;
mod uci;

pub struct Enforcer {
    pub client: RPCClient,
    pub config: EnforcerConfig,
}

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

    info!("Trying to find & connect to NAMIB Controller");
    let mut client = rpc::rpc_client::run().await?;
    // todo read config from file
    let config = client
        .heartbeat(current_rpc_context(), None)
        .await?
        .expect("no initial config sent from controller");
    let enforcer: Arc<RwLock<Enforcer>> = Arc::new(RwLock::new(Enforcer { client, config }));
    info!("Connected to NAMIB Controller RPC server");

    let mut dns_service = services::dns::DnsService::new().unwrap();

    let watcher = dns_service.create_watcher();
    let fw_service = Arc::new(FirewallService::new(enforcer.clone(), watcher));

    let heartbeat_task = rpc::rpc_client::heartbeat(enforcer.clone(), fw_service.clone());

    let dhcp_event_task = dhcp::dhcp_event_listener::listen_for_dhcp_events(enforcer.clone());

    let dns_task = tokio::spawn(async move {
        dns_service.auto_refresher_task().await;
    });
    let _log_watcher = thread::spawn(move || services::log_watcher::watch(&enforcer));

    let firewall_task = tokio::spawn(async move {
        fw_service.firewall_change_watcher().await;
    });

    tokio::join!(heartbeat_task, dhcp_event_task, dns_task, firewall_task);
    Ok(())
}
