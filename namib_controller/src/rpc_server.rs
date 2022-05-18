// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use futures::{future, stream, StreamExt, TryStreamExt};
use namib_shared::{
    codec,
    flow_scope::FlowData,
    models::DhcpEvent,
    rpc::NamibRpc,
    tarpc::{
        context, serde_transport,
        serde_transport::Transport,
        server,
        server::{BaseChannel, Channel},
    },
    EnforcerConfig,
};
use rustls::{RootCertStore, ServerSession, Session};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tokio_stream::wrappers::TcpListenerStream;
use tokio_util::codec::LengthDelimitedCodec;

use crate::{
    app_config::APP_CONFIG,
    db::DbConnection,
    error::Result,
    models::{AdministrativeContext, ConfiguredServerDbo, DefinedServer},
    services::{acme_service::CertId, device_service, enforcer_service, firewall_configuration_service, log_service},
    util::open_file_with,
};

#[derive(Clone)]
pub struct NamibRpcServer {
    pub client_ip: SocketAddr,
    pub client_id: CertId,
    pub db_connection: DbConnection,
}

#[server]
impl NamibRpc for NamibRpcServer {
    /// Called regularly by the enforcer to refresh its state.
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
            let administrative_context =
                create_administrative_context(&self.db_connection)
                    .await
                    .unwrap_or_else(|err| {
                        error!("there was an error creating the administrative context: '{}'", err);
                        AdministrativeContext::default()
                    });
            let new_config = firewall_configuration_service::create_configuration(
                &self.db_connection,
                current_config_version,
                &init_devices,
                &administrative_context,
            )
            .await;
            debug!("Returning Heartbeat to client with config: {:?}", new_config.version());
            return Some(new_config);
        }

        None
    }

    /// Called when the enforcer receives a dhcp lease event.
    #[allow(clippy::pedantic)]
    async fn dhcp_request(self, _: context::Context, dhcp_event: DhcpEvent) {
        debug!("dhcp_request from: {:?}. Data: {:?}", self.client_ip, dhcp_event);

        // TODO: Handle different dhcp event lease types (currently handles everything as "add")
        let lease_info = match dhcp_event {
            DhcpEvent::LeaseAdded { lease_info, .. } | DhcpEvent::ExistingLeaseUpdate { lease_info, .. } => lease_info,
            _ => return,
        };

        if let Err(e) = device_service::upsert_device_from_dhcp_lease(lease_info, &self.db_connection).await {
            error!("Failed to upsert device from dhcp lease {:?}", e)
        }
    }

    /// Called when the enforcer reads new dns logs
    async fn send_logs(self, _: context::Context, logs: Vec<String>) {
        debug!(
            "send_logs from {:?} ({}): logs {}",
            self.client_ip,
            self.client_id,
            logs.len(),
        );
        log_service::add_new_logs(self.client_id, logs, &self.db_connection).await;
    }

    async fn send_scope_results(self, _: context::Context, _results: Vec<FlowData>) {
        // Add services here
    }
}

async fn create_administrative_context(pool: &DbConnection) -> Result<AdministrativeContext> {
    let context = AdministrativeContext {
        dns_mappings: sqlx::query_as!(ConfiguredServerDbo, "SELECT * FROM dns_servers")
            .fetch_all(pool)
            .await?
            .iter()
            .map(|dbo| {
                if let Ok(ip) = dbo.server.parse::<IpAddr>() {
                    DefinedServer::Ip(ip)
                } else {
                    DefinedServer::Url(dbo.server.clone())
                }
            })
            .collect(),
        ntp_mappings: sqlx::query_as!(ConfiguredServerDbo, "SELECT * FROM ntp_servers")
            .fetch_all(pool)
            .await?
            .iter()
            .map(|dbo| {
                if let Ok(ip) = dbo.server.parse::<IpAddr>() {
                    DefinedServer::Ip(ip)
                } else {
                    DefinedServer::Url(dbo.server.clone())
                }
            })
            .collect(),
    };

    Ok(context)
}

/// Advertise the rpc server via dnssd and listen for incoming rpc connections.
pub async fn listen(pool: DbConnection) -> Result<()> {
    debug!("Registering in dnssd");
    let (_registration, result) = async_dnssd::register("_namib_controller._tcp", APP_CONFIG.rpc_port)?.await?;
    info!("Registered: {:?}", result);

    // Build TLS configuration.
    let tls_cfg = {
        // Use client certificate authentication.
        let mut client_auth_roots = RootCertStore::empty();
        open_file_with(&APP_CONFIG.namib_ca_cert, |b| client_auth_roots.add_pem_file(b))?;

        // Load server cert
        let certs = open_file_with(&APP_CONFIG.namib_server_cert, rustls::internal::pemfile::certs)
            .expect("Could not find NAMIB_SERVER_CERT");
        let key = open_file_with(
            &APP_CONFIG.namib_server_key,
            rustls::internal::pemfile::rsa_private_keys,
        )
        .expect("Could not find NAMIB_SERVER_KEY")[0]
            .clone();

        let mut cfg = rustls::ServerConfig::new(rustls::AllowAnyAuthenticatedClient::new(client_auth_roots));
        cfg.set_single_cert(certs, key)?;

        Arc::new(cfg)
    };
    let v4_addr = SocketAddr::new("0.0.0.0".parse()?, APP_CONFIG.rpc_port);
    let v6_addr = SocketAddr::new("::".parse()?, APP_CONFIG.rpc_port);
    info!("Starting to serve on {} and {}.", v4_addr, v6_addr);
    let tcp_stream = {
        let v4_stream = TcpListenerStream::new(TcpListener::bind(v4_addr).await?);
        // attempt binding to the ipv6 address and create a merged stream if successful.
        if let Ok(v6_listener) = TcpListener::bind(v6_addr).await {
            stream::select(v4_stream, TcpListenerStream::new(v6_listener)).boxed()
        } else {
            v4_stream.boxed()
        }
    };

    // Create a tls acceptor that wraps a tcp acceptor.
    let acceptor = TlsAcceptor::from(tls_cfg);
    tcp_stream
        .and_then(|str| acceptor.accept(str))
        .map_ok(|tlsstr| {
            serde_transport::new(
                LengthDelimitedCodec::builder()
                    .max_frame_length(50 * 1024 * 1024) // max packet size is 50 MB
                    .new_framed(tlsstr),
                codec(),
            )
        })
        // Ignore accept errors.
        .inspect_err(|err| warn!("Failed to accept {:?}", err))
        .filter_map(|r| future::ready(r.ok()))
        .map(BaseChannel::with_defaults)
        .filter_map(|channel| {
            let client_ip = channel.get_tcp_stream().peer_addr().unwrap();
            let client_id = CertId::new(channel.get_tls_session().get_peer_certificates().unwrap()[0].as_ref());
            let db_connection = pool.clone();

            async move {
                if let Err(e) = enforcer_service::register_enforcer(&db_connection, client_ip.ip(), &client_id).await {
                    warn!("Not accepting enforcer connection {:?}", e);
                    return None;
                }
                let server = NamibRpcServer {
                    client_ip,
                    client_id,
                    db_connection,
                };
                Some(channel.requests().execute(server.serve()))
            }
        })
        // max 10 connections
        .buffer_unordered(10)
        .for_each(|_| async {})
        .await;

    info!("done");

    Ok(())
}

trait BaseChannelExt {
    fn get_tcp_stream(&self) -> &TcpStream;
    fn get_tls_session(&self) -> &ServerSession;
}

impl<A, B, Item, SinkItem, Codec> BaseChannelExt
    for BaseChannel<A, B, Transport<TlsStream<TcpStream>, Item, SinkItem, Codec>>
{
    /// Unwrap a `BaseChannel` wrapping a `TlsStream` and retrieve a reference to its `TcpStream`
    fn get_tcp_stream(&self) -> &TcpStream {
        self.as_ref().get_ref().get_ref().0
    }

    /// Unwrap a `BaseChannel` wrapping a `TlsStream` and retrieve a reference to its tls `ServerSession`
    fn get_tls_session(&self) -> &ServerSession {
        self.as_ref().get_ref().get_ref().1
    }
}
