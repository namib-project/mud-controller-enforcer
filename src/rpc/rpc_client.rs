use std::{net::SocketAddr, sync::Arc};

use crate::services::config_firewall_service;
use futures::{pin_mut, prelude::*};
use snafu::{Backtrace, GenerateBacktrace};
use tarpc::{client, context};
use tokio::{
    sync::Mutex,
    time::{sleep, Duration},
};
use tokio_rustls::{rustls, webpki::DNSNameRef};

use namib_shared::{codec, open_file_with, rpc::RPCClient};

use crate::error::{Error, Result};

use super::{controller_discovery::discover_controllers, tls_serde_transport};

pub async fn run() -> Result<RPCClient> {
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

    let addr_stream = discover_controllers("_namib_controller._tcp")?
        .try_filter_map(|addr| try_connect(addr.into(), dns_name, tls_cfg.clone()))
        .inspect_err(|err| warn!("Failed to connect to controller: {:?}", err))
        .filter_map(|r| future::ready(r.ok()));
    pin_mut!(addr_stream);

    match addr_stream.next().await {
        Some(client) => Ok(client),
        None => Err(Error::ConnectionError {
            message: "No Client",
            backtrace: Backtrace::generate(),
        }),
    }
}

pub async fn heartbeat(client: Arc<Mutex<RPCClient>>) {
    loop {
        {
            let mut instance = client.lock().await;
            match instance.heartbeat(context::current(), config_firewall_service::get_config_version()).await {
                Err(error) => error!("Error during heartbeat: {:?}", error),
                Ok(config) => {
                    // Option<Vec<ConfigFirewall>>
                    debug!("Heartbeat OK!");
                    match config {
                        None => {},
                        Some(config) => {
                            debug!("Received new config {:#?}", config);
                            config_firewall_service::apply_config(config);
                        },
                    }
                },
            }

            drop(instance);
        }

        sleep(Duration::from_secs(5)).await;
    }
}

async fn try_connect(addr: SocketAddr, dns_name: DNSNameRef<'static>, cfg: Arc<rustls::ClientConfig>) -> Result<Option<RPCClient>> {
    debug!("trying to connect to address {:?}", addr);

    // ip6 geht anscheinend nicht
    if let SocketAddr::V6(_) = addr {
        return Ok(None);
    }

    let mut transport = tls_serde_transport::connect(cfg, dns_name, addr, codec());
    transport.config_mut().max_frame_length(50 * 1024 * 1024);

    Ok(Some(RPCClient::new(client::Config::default(), transport.await?).spawn()?))
}
