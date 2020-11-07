use std::net::SocketAddr;
use std::sync::Arc;

use futures::{
    pin_mut,
    prelude::*,
};
use log::*;
use tarpc::{client, context};
use tokio::time::{Duration, sleep};
use tokio_rustls::rustls;
use tokio_rustls::webpki::DNSNameRef;

use namib_shared::{codec, open_file_with};
use namib_shared::rpc::*;

use crate::error::*;

use super::controller_discovery::discover_controllers;
use super::tls_serde_transport;

pub async fn run() -> Result<()> {
    let tls_cfg = {
        // set client auth cert
        let certificate = open_file_with("certs/client.pem", rustls::internal::pemfile::certs)?;
        let private_key = open_file_with("certs/client-key.pem", rustls::internal::pemfile::rsa_private_keys)?[0].clone();
        let mut config = rustls::ClientConfig::new();
        config.set_single_client_cert(certificate, private_key)?;

        // verify server cert using CA
        open_file_with("../namib_shared/certs/ca.pem", |b| config.root_store.add_pem_file(b))?;

        Arc::new(config)
    };

    let dns_name = DNSNameRef::try_from_ascii(b"_controller._namib")?;

    let mut client = {
        let addr_stream = discover_controllers("_namib_controller._tcp")?
            .and_then(|addr| try_connect(addr.into(), dns_name, tls_cfg.clone()))
            .inspect_err(|err| warn!("Failed to connect to controller: {:?}", err))
            .filter_map(|r| future::ready(r.ok()));
        pin_mut!(addr_stream);

        addr_stream.next().await
    };

    match &mut client {
        Some(client) => {
            info!("Connected to RPC server");
            loop {
                client.heartbeat(context::current()).await?;
                debug!("Heartbeat OK!");

                sleep(Duration::from_secs(5)).await;
            }
        }
        None => {
            error!("Failed to find a server");
        }
    }

    info!("done!");
    return Ok(());
}

async fn try_connect(addr: SocketAddr, dns_name: DNSNameRef<'static>, cfg: Arc<rustls::ClientConfig>) -> Result<RPCClient> {
    debug!("trying to connect to address {:?}", addr);

    // ip6 geht anscheinend nicht
    if let SocketAddr::V6(_) = addr {
        ConnectionError { message: "IPv6 is not supported" }.fail()?;
    }

    let mut transport = tls_serde_transport::connect(cfg, dns_name, addr, codec());
    transport.config_mut().max_frame_length(4294967296);

    Ok(RPCClient::new(client::Config::default(), transport.await?).spawn()?)
}