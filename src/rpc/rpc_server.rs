use std::{env, net::SocketAddr, sync::Arc};

use futures::{future, StreamExt, TryStreamExt};
use rustls::RootCertStore;
use tarpc::{
    context,
    rpc::server::{BaseChannel, Channel, Handler},
    server,
};

use namib_shared::{
    codec,
    config_firewall::{FirewallConfig, FirewallRule},
    models::DhcpEvent,
    open_file_with,
    rpc::RPC,
};

use crate::{
    db::DbConnection,
    error::Result,
    models::Device,
    services::{config_firewall_service, device_service, mud_service},
};

use super::tls_serde_transport;
use namib_shared::config_firewall::FirewallDevice;

#[derive(Clone)]
pub struct RPCServer(SocketAddr, DbConnection);

#[server]
impl RPC for RPCServer {
    async fn heartbeat(self, _: context::Context, version: Option<String>) -> Option<FirewallConfig> {
        let current_config_version = config_firewall_service::get_config_version(&self.1).await;
        debug!(
            "Received a heartbeat from client {:?} with version {:?}, current version {:?}",
            self.0, version, current_config_version
        );
        if Some(&current_config_version) != version.as_ref() {
            debug!(
                "Client has outdated version \"{}\". Starting update...",
                current_config_version
            );
            let devices = device_service::get_all_devices(&self.1).await.unwrap_or_default();
            debug!("heartbeat all devices {:?}", devices);
            let device_configs: Vec<FirewallDevice> = devices
                .iter()
                .flat_map(move |d| {
                    config_firewall_service::convert_device_to_fw_rules(d)
                        .map_err(|err| error!("Flat Map Error {:#?}", err))
                        .ok()
                })
                .collect();

            debug!("Returning Heartbeat to client with config: {:?}", device_configs);
            return Some(FirewallConfig::new(current_config_version, device_configs));
        }

        None
    }

    async fn dhcp_request(self, _: context::Context, dhcp_event: DhcpEvent) {
        debug!("dhcp_request from: {:?}. Data: {:?}", self.0, dhcp_event);

        // TODO: Handle different dhcp event lease types (currently handles everything as "add")
        let lease_info = match dhcp_event {
            DhcpEvent::LeaseAdded { lease_info, .. } => lease_info,
            _ => return,
        };

        let mut dhcp_device_data = Device::from(lease_info);
        let update = match device_service::find_by_ip(dhcp_device_data.ip_addr, &self.1).await {
            Ok(device) => {
                dhcp_device_data.id = device.id;
                true
            },
            Err(_) => false,
        };

        debug!("dhcp request device mud file: {:?}", dhcp_device_data.mud_url);

        match &dhcp_device_data.mud_url {
            Some(url) => match mud_service::get_mud_from_url(url.clone(), &self.1).await {
                Ok(mud_data) => Some(mud_data),
                Err(err) => {
                    info!("Error parsing mud file from URL {}: {:?}", url, err);
                    None
                },
            },
            None => None,
        };

        if update {
            device_service::update_device(&dhcp_device_data, &self.1).await.unwrap();
        } else {
            device_service::insert_device(&dhcp_device_data, &self.1).await.unwrap();
        }

        config_firewall_service::update_config_version(&self.1).await;
    }
}

pub async fn listen(pool: DbConnection) -> Result<()> {
    debug!("Registering in dnssd");
    let (_registration, result) = async_dnssd::register("_namib_controller._tcp", 8734)?.await?;
    info!("Registered: {:?}", result);

    // Build TLS configuration.
    let tls_cfg = {
        // Use client certificate authentication.
        let mut client_auth_roots = RootCertStore::empty();
        open_file_with(&env::var("NAMIB_CA_CERT").expect("NAMIB_CA_CERT env is missing"), |b| {
            client_auth_roots.add_pem_file(b)
        })?;

        // Load server cert
        let certs = open_file_with("certs/server.pem", rustls::internal::pemfile::certs)
            .expect("Could not find certs/server.pem");
        let key = open_file_with("certs/server-key.pem", rustls::internal::pemfile::rsa_private_keys)
            .expect("Could not find certs/server-key.pem")[0]
            .clone();

        let mut cfg = rustls::ServerConfig::new(rustls::AllowAnyAuthenticatedClient::new(client_auth_roots));
        cfg.set_single_cert(certs, key)?;

        Arc::new(cfg)
    };

    let addr: SocketAddr = "0.0.0.0:8734".parse()?;
    info!("Starting to serve on {}.", addr);

    // Create a TLS listener via tokio.
    let mut listener = tls_serde_transport::listen(tls_cfg, addr, codec()).await?;
    listener.config_mut().max_frame_length(50 * 1024 * 1024);
    listener
        // Ignore accept errors.
        .inspect_err(|err| warn!("Failed to accept {:?}", err))
        .filter_map(|r| future::ready(r.ok()))
        .map(BaseChannel::with_defaults)
        // Limit channels to 1 per IP.
        .max_channels_per_key(1, |t| t.get_ref().get_ref().get_ref().0.peer_addr().unwrap().ip())
        // serve is generated by the service attribute. It takes as input any type implementing
        // the generated World trait.
        .map(|channel| {
            let server = RPCServer(
                channel.get_ref().get_ref().get_ref().get_ref().0.peer_addr().unwrap(),
                pool.clone(),
            );
            channel.respond_with(server.serve()).execute()
        })
        // Max 10 channels.
        .buffer_unordered(10)
        .for_each(|_| async {})
        .await;

    info!("done");

    Ok(())
}
