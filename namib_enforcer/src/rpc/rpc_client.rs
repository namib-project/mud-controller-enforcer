// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{env, io, net::SocketAddr, sync::Arc, time::SystemTime};

use futures::{pin_mut, prelude::*};
use namib_shared::{
    codec,
    rpc::NamibRpcClient,
    tarpc::{client, context, serde_transport},
    EnforcerConfig,
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, ErrorKind},
    net::TcpStream,
    sync::RwLock,
    time::{sleep, Duration},
};
use tokio_native_tls::{
    native_tls,
    native_tls::{Certificate, Identity},
    TlsConnector,
};
use tokio_util::codec::LengthDelimitedCodec;

use super::controller_discovery::discover_controllers;
use crate::{
    error::Result,
    services::{controller_name::apply_secure_name_config, firewall_service::FirewallService},
    Enforcer,
};

pub async fn run() -> Result<(NamibRpcClient, SocketAddr)> {
    let identity = {
        // set client auth cert
        let mut vec = Vec::new();
        let mut file = File::open(env::var("NAMIB_IDENTITY").expect("NAMIB_IDENTITY env is missing")).await?;
        file.read_to_end(&mut vec).await?;
        Identity::from_pkcs12(&vec, "client")?
    };
    let ca = {
        // verify server cert using CA
        let mut vec = Vec::new();
        let mut file = File::open(env::var("NAMIB_CA_CERT").expect("NAMIB_CA_CERT env is missing")).await?;
        file.read_to_end(&mut vec).await?;
        Certificate::from_pem(&vec)?
    };

    loop {
        let addr_stream = discover_controllers("_namib_controller._tcp")
            .try_filter_map(|addr| try_connect(addr.into(), "_controller._namib", identity.clone(), ca.clone()))
            .inspect_err(|err| warn!("Failed to connect to controller: {:?}", err))
            .filter_map(|r| future::ready(r.ok()));
        pin_mut!(addr_stream);

        if let Some(client) = addr_stream.next().await {
            info!("Connected to NAMIB Controller RPC server");
            return Ok(client);
        }

        warn!("No controller found, retrying in 5 secs");
        sleep(Duration::from_secs(5)).await;
    }
}

pub async fn heartbeat(enforcer: Arc<RwLock<Enforcer>>, fw_service: Arc<FirewallService>) {
    loop {
        {
            let enf = enforcer.read().await;
            let version = Some(enf.config.version().into());
            let heartbeat: io::Result<Option<EnforcerConfig>> = enf
                .client
                .heartbeat(context::current(), version, enf.config.expiration_date_time())
                .await;
            match heartbeat {
                Err(error) => match error.kind() {
                    ErrorKind::ConnectionReset => {
                        error!("RPC Server connection reset, trying to reconnect... ({:?})", error);
                        if let Ok((new_client, addr)) = run().await {
                            drop(enf);
                            let mut enf = enforcer.write().await;
                            enf.client = new_client;
                            enf.addr = addr;
                        }
                    },
                    _ => {
                        error!("Error during heartbeat: {:?}", error);
                    },
                },
                Ok(Some(config)) => {
                    trace!("Received new config {:?}", config);
                    if enf.config.secure_name() != config.secure_name() {
                        if let Err(e) = apply_secure_name_config(enf.config.secure_name(), enf.addr) {
                            error!("Error while applying new controller address: {:?}", e);
                        }
                    }
                    drop(enf);
                    // Apply new config and notify firewall service.
                    enforcer.write().await.apply_new_config(config).await;
                    fw_service.notify_firewall_change();
                },
                Ok(None) => debug!("Heartbeat OK!"),
            }
        }

        sleep(Duration::from_secs(5)).await;
    }
}

async fn try_connect(
    addr: SocketAddr,
    dns_name: &'static str,
    identity: Identity,
    ca: Certificate,
) -> Result<Option<(NamibRpcClient, SocketAddr)>> {
    debug!("trying to connect to address {:?}", addr);

    let tcp_stream = TcpStream::connect(addr).await?;
    let tls_connector = TlsConnector::from(
        native_tls::TlsConnector::builder()
            .identity(identity)
            .disable_built_in_roots(true)
            .add_root_certificate(ca)
            .build()?,
    );
    let framed_io = LengthDelimitedCodec::builder()
        .max_frame_length(50 * 1024 * 1024)
        .new_framed(tls_connector.connect(dns_name, tcp_stream).await?);
    let transport = serde_transport::new(framed_io, codec());

    Ok(Some((
        NamibRpcClient::new(client::Config::default(), transport).spawn(),
        addr,
    )))
}

/// Returns the context for the current request, or a default Context if no request is active.
/// Copied and adapted based on tarpc/rpc/context.rs
pub fn current_rpc_context() -> context::Context {
    let mut rpc_context = context::current();
    rpc_context.deadline = SystemTime::now() + Duration::from_secs(60); // The deadline is the timestamp, when the request should be dropped, if not already responded to
    rpc_context
}
