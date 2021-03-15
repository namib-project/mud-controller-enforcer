#![warn(clippy::all, clippy::style, clippy::pedantic)]
#![allow(dead_code, clippy::module_name_repetitions)]

#[macro_use]
extern crate log;

use std::sync::Arc;

use dotenv::dotenv;
use tokio::{fs, fs::OpenOptions};

use crate::{rpc::rpc_client::current_rpc_context, services::firewall_service::FirewallService};
use error::Result;
use namib_shared::{firewall_config::EnforcerConfig, rpc::RPCClient};
use std::{env, path::Path, thread};
use tokio::sync::RwLock;

mod dhcp;
mod error;
mod rpc;
mod services;
mod uci;

const DEFAULT_CONFIG_STATE_FILE: &str = "/etc/namib/state.json";

pub struct Enforcer {
    pub client: RPCClient,
    pub config: EnforcerConfig,
}

impl Enforcer {
    pub(crate) async fn apply_new_config(&mut self, config: EnforcerConfig) {
        self.config = config;
        persist_config(&self.config).await;
    }
}

async fn persist_config(config: &EnforcerConfig) {
    let config_state_path = env::var("NAMIB_CONFIG_STATE_FILE").unwrap_or(String::from(DEFAULT_CONFIG_STATE_FILE));
    let config_state_path = Path::new(config_state_path.as_str());
    if let Some(parent_dir) = config_state_path.parent() {
        fs::create_dir_all(&parent_dir)
            .await
            .unwrap_or_else(|e| warn!("Error while creating config state parent directory: {:?}", e));
    };
    match serde_json::to_vec(&config) {
        Ok(serialised_bytes) => {
            fs::write(config_state_path.clone(), serialised_bytes)
                .await
                .and_then(|_| {
                    debug!(
                        "Persisted configuration at path \"{}\"",
                        config_state_path.to_string_lossy()
                    );
                    Ok(())
                })
                .unwrap_or_else(|e| warn!("Error while persisting config state: {:?}", e));
        },
        Err(e) => {
            warn!("Error while serialising config state: {:?}", e);
        },
    }
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
    info!("Reading last saved enforcer state");
    let config_state_path = env::var("NAMIB_CONFIG_STATE_FILE").unwrap_or(String::from(DEFAULT_CONFIG_STATE_FILE));
    let config: Option<EnforcerConfig> = match fs::read(config_state_path)
        .await
        .map(|state_bytes| serde_json::from_slice(state_bytes.as_slice()))
    {
        Ok(Ok(v)) => Some(v),
        Err(err) => {
            warn!("Error while reading config state file: {:?}", err);
            None
        },
        Ok(Err(err)) => {
            warn!("Error while deserializing config state file: {:?}", err);
            None
        },
    };

    info!("Trying to find & connect to NAMIB Controller");
    let mut client = rpc::rpc_client::run().await?;
    let config = match config {
        Some(v) => {
            info!("Successfully restored last persisted config");
            v
        },
        None => {
            info!("Retrieving initial config from NAMIB Controller");
            let init_config = client
                .heartbeat(current_rpc_context(), None)
                .await?
                .expect("no initial config sent from controller");
            persist_config(&init_config).await;
            info!("Successfully retrieved initial configuration from NAMIB controller");
            init_config
        },
    };

    // todo read config from file
    let enforcer: Arc<RwLock<Enforcer>> = Arc::new(RwLock::new(Enforcer { client, config }));
    info!("Connected to NAMIB Controller RPC server");

    let mut dns_service = services::dns::DnsService::new().unwrap();

    let watcher = dns_service.create_watcher();
    let fw_service = Arc::new(FirewallService::new(enforcer.clone(), watcher));
    fw_service.apply_current_config().await?;

    let heartbeat_task = rpc::rpc_client::heartbeat(enforcer.clone(), fw_service.clone());

    let dhcp_event_task = dhcp::dhcp_event_listener::listen_for_dhcp_events(enforcer.clone());

    let dns_task = tokio::spawn(async move {
        dns_service.auto_refresher_task().await;
    });
    let _log_watcher = thread::spawn(move || services::log_watcher::watch(&enforcer));

    let firewall_task = tokio::spawn(async move {
        fw_service.firewall_change_watcher().await;
    });

    let ((), (), dns_result, firewall_result) = tokio::join!(heartbeat_task, dhcp_event_task, dns_task, firewall_task);
    dns_result.and(firewall_result)?;
    Ok(())
}
