use std::{env, net::SocketAddr, sync::Arc};

use futures::{future, stream, StreamExt, TryStreamExt};
use rustls::{RootCertStore, ServerSession, Session};
use tarpc::{
    context, serde_transport,
    serde_transport::Transport,
    server,
    server::{BaseChannel, Channel, Incoming},
};

use namib_shared::{codec, firewall_config::EnforcerConfig, models::DhcpEvent, open_file_with, rpc::NamibRpc};

use crate::{
    db::DbConnection,
    error::Result,
    services::{device_service, firewall_configuration_service},
};

use crate::services::{acme_service::CertId, log_service};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tokio_stream::wrappers::TcpListenerStream;
use tokio_util::codec::LengthDelimitedCodec;

#[derive(Clone)]
pub struct NamibRpcServer {
    pub client_ip: SocketAddr,
    pub client_id: CertId,
    pub db_connection: DbConnection,
}

#[server]
impl NamibRpc for NamibRpcServer {
    async fn heartbeat(self, _: context::Context, version: Option<String>) -> Option<EnforcerConfig> {
        let current_config_version = firewall_configuration_service::get_config_version(&self.db_connection).await;
        debug!(
            "heartbeat from {:?} ({}): version {:?}, current version {:?}",
            self.client_ip, self.client_id, version, current_config_version
        );
        if Some(&current_config_version) != version.as_ref() {
            debug!("Client has outdated version. Starting update...");
            let devices = device_service::get_all_devices(&self.db_connection)
                .await
                .unwrap_or_default();
            let init_devices: Vec<_> = stream::iter(devices)
                .then(|d| d.load_refs(&self.db_connection))
                .try_collect()
                .await
                .unwrap_or_default();
            let new_config =
                firewall_configuration_service::create_configuration(current_config_version, &init_devices);
            debug!("Returning Heartbeat to client with config: {:?}", new_config.version());
            return Some(new_config);
        }

        None
    }

    async fn dhcp_request(self, _: context::Context, dhcp_event: DhcpEvent) {
        debug!("dhcp_request from: {:?}. Data: {:?}", self.client_ip, dhcp_event);

        // TODO: Handle different dhcp event lease types (currently handles everything as "add")
        let lease_info = match dhcp_event {
            DhcpEvent::LeaseAdded { lease_info, .. } => lease_info,
            _ => return,
        };

        if let Err(e) = device_service::upsert_device_from_dhcp_lease(lease_info, &self.db_connection).await {
            error!("Failed to upsert device from dhcp lease {:?}", e)
        }
    }

    async fn send_logs(self, _: context::Context, logs: Vec<String>) {
        debug!(
            "send_logs from {:?} ({}): logs {:?}",
            self.client_ip,
            self.client_id,
            logs.len(),
        );
        log_service::add_new_logs(self.client_id, logs, &self.db_connection).await
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
    let acceptor = TlsAcceptor::from(tls_cfg);
    TcpListenerStream::new(TcpListener::bind(addr).await?)
        .and_then(|str| acceptor.accept(str))
        .map_ok(|tlsstr| {
            serde_transport::new(
                LengthDelimitedCodec::builder()
                    .max_frame_length(50 * 1024 * 1024)
                    .new_framed(tlsstr),
                codec(),
            )
        })
        // Ignore accept errors.
        .inspect_err(|err| warn!("Failed to accept {:?}", err))
        .filter_map(|r| future::ready(r.ok()))
        .map(BaseChannel::with_defaults)
        // limit to 1 connection per ip
        .max_channels_per_key(1, |t| get_streams(t).0.peer_addr().unwrap().ip())
        .map(|channel| {
            let streams = get_streams(channel.as_ref());
            let server = NamibRpcServer {
                client_ip: streams.0.peer_addr().unwrap(),
                // the fingerprint of a certificate is the sha1 of its entire bytes encoded in DER
                client_id: CertId::new(streams.1.get_peer_certificates().unwrap()[0].as_ref()),
                db_connection: pool.clone(),
            };
            channel.requests().execute(server.serve())
        })
        // max 10 connections
        .buffer_unordered(10)
        .for_each(|_| async {})
        .await;

    info!("done");

    Ok(())
}

fn get_streams<A, B, Item, SinkItem, Codec>(
    channel: &BaseChannel<A, B, Transport<TlsStream<TcpStream>, Item, SinkItem, Codec>>,
) -> (&TcpStream, &ServerSession) {
    channel.as_ref().get_ref().get_ref()
}
