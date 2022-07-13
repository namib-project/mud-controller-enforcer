// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

#![warn(clippy::all, clippy::style, clippy::pedantic)]
#![allow(dead_code, clippy::module_name_repetitions)]

#[macro_use]
extern crate log;

use chrono::Utc;
use std::{env, fs::File, net::SocketAddr, path::Path, sync::Arc, thread};

use dotenv::dotenv;
use error::{Error, Result};
use namib_shared::{rpc::NamibRpcClient, EnforcerConfig};
use tokio::{fs, fs::OpenOptions, sync::RwLock};

use crate::{
    rpc::rpc_client::current_rpc_context,
    services::{
        controller_name::apply_secure_name_config,
        firewall_service::{apply_firewall_config_inner, FirewallService},
    },
};

mod dhcp;
mod error;
mod rpc;
mod services;
mod uci;

/// Default location for the file containing the last received enforcer configuration.
const DEFAULT_CONFIG_STATE_FILE: &str = "/etc/namib/state.json";

pub struct Enforcer {
    pub client: NamibRpcClient,
    pub addr: SocketAddr,
    pub config: EnforcerConfig,
}

impl Enforcer {
    /// Applies a new enforcer configuration and persists it to the filesystem for the next start.
    pub(crate) async fn apply_new_config(&mut self, config: EnforcerConfig) {
        self.config = config;
        persist_config(&self.config).await;
    }
}

/// Persists a given enforcer configuration to the filesystem at the location specified by the `NAMIB_CONFIG_STATE_FILE`
/// environment variable (or `DEFAULT_CONFIG_STATE_FILE` if the environment variable is not set).
async fn persist_config(config: &EnforcerConfig) {
    let config_state_path =
        env::var("NAMIB_CONFIG_STATE_FILE").unwrap_or_else(|_| String::from(DEFAULT_CONFIG_STATE_FILE));
    let config_state_path = Path::new(config_state_path.as_str());
    if let Some(parent_dir) = config_state_path.parent() {
        fs::create_dir_all(&parent_dir)
            .await
            .unwrap_or_else(|e| warn!("Error while creating config state parent directory: {:?}", e));
    };
    if let Err(e) = File::create(config_state_path)
        .map_err(Error::from)
        .and_then(|file| Ok(serde_json::to_writer(&file, &config)?))
    {
        warn!("Error while persisting config state: {:?}", e);
        return;
    }
    debug!("Persisted configuration at path \"{}\"", config_state_path.display());
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    dotenv().ok();
    env_logger::init();

    info!(
        "Starting in {} mode",
        if services::is_system_mode() { "SYSTEM" } else { "USER" }
    );
    // Create uci config file if it doesn't exist
    if !services::is_system_mode() {
        fs::create_dir_all("config").await?;
        OpenOptions::new().write(true).create(true).open("config/dhcp").await?;
    }

    // Attempt to read last persisted enforcer state.
    info!("Reading last saved enforcer state");
    let config_state_path =
        env::var("NAMIB_CONFIG_STATE_FILE").unwrap_or_else(|_| DEFAULT_CONFIG_STATE_FILE.to_string());
    let config: Option<EnforcerConfig> = match File::open(config_state_path)
        .map_err(Error::from)
        .and_then(|file| Ok(serde_json::from_reader(file)?))
    {
        Ok(v) => Some(v),
        Err(err) => {
            warn!("Error while reading config state file: {:?}", err);
            None
        },
    };

    // Restore enforcer config if persisted file could be restored, otherwise wait for the enforcer
    // to provide an initial configuration.
    // Create enforcer instance with provided RPC Client if initial config has been retrieved, with no RPC Client (yet) otherwise.
    let mut connected_enforcer = None;
    let config = if let Some(config) = config {
        info!("Successfully restored last persisted config");
        config
    } else {
        info!("Retrieving initial config from NAMIB Controller");
        let (client, addr) = rpc::rpc_client::run().await?;
        let config = client
            .heartbeat(current_rpc_context(), None, Some(Utc::now().naive_local()))
            .await?
            .expect("no initial config sent from controller");
        persist_config(&config).await;
        info!("Successfully retrieved initial configuration from NAMIB controller");
        connected_enforcer = Some(Arc::new(RwLock::new(Enforcer {
            client,
            addr,
            config: config.clone(),
        })));
        config
    };

    // Instantiate DNS resolver service.
    let mut dns_service = services::dns::DnsService::new().unwrap();

    // Instantiate firewall service with DNS watcher.
    let watcher = dns_service.create_watcher();

    apply_firewall_config_inner(&config, &watcher).await?;

    // If the RPC client was not already retrieved while getting the initial config, get it now.
    let enforcer = match connected_enforcer {
        None => {
            let (client, addr) = rpc::rpc_client::run().await?;
            Arc::new(RwLock::new(Enforcer { client, addr, config }))
        },
        Some(e) => e,
    };

    // Enforcer is now guaranteed to have an RPC client and a server address.
    {
        let enforcer_read_lock = enforcer.read().await;
        apply_secure_name_config(enforcer_read_lock.config.secure_name(), enforcer_read_lock.addr)?;
    }

    // Create the firewall service
    let fw_service = Arc::new(FirewallService::new(enforcer.clone(), watcher));

    let heartbeat_task = tokio::spawn(rpc::rpc_client::heartbeat(enforcer.clone(), fw_service.clone()));
    let dhcp_event_task = tokio::spawn(dhcp::dhcp_event_listener::listen_for_dhcp_events(enforcer.clone()));
    let dns_task = tokio::spawn(async move { dns_service.auto_refresher_task().await });
    let firewall_task = tokio::spawn(async move { fw_service.firewall_change_watcher().await });
    let np0f_log_task = tokio::spawn(services::log_watcher::watch_np0f(enforcer.clone()));
    let nflog_task = tokio::spawn(services::nflog_watcher::watch(enforcer.clone()));

    let _log_watcher = thread::spawn(move || services::log_watcher::watch(&enforcer));

    tokio::try_join!(
        heartbeat_task,
        dhcp_event_task,
        dns_task,
        firewall_task,
        np0f_log_task,
        nflog_task
    )?;
    Ok(())
}
