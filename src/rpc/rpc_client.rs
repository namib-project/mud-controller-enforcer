use std::{env, io, net::SocketAddr, sync::Arc};

use futures::{pin_mut, prelude::*};
use snafu::{Backtrace, GenerateBacktrace};
use tarpc::{client, context, serde_transport};
use tokio::{
    sync::Mutex,
    time::{sleep, Duration},
};

use namib_shared::{codec, config_firewall::FirewallConfig, rpc::RPCClient};

use crate::{
    error::{Error, Result},
    services::firewall_service,
};

use super::controller_discovery::discover_controllers;
use crate::{
    models::model_firewall::FirewallConfigState,
    services::{firewall_service::FirewallService, state::EnforcerState},
};
use tokio::{fs::File, io::AsyncReadExt, net::TcpStream};
use tokio_native_tls::{
    native_tls,
    native_tls::{Certificate, Identity},
    TlsConnector,
};
use tokio_util::codec::LengthDelimitedCodec;

pub async fn run() -> Result<RPCClient> {
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

    let addr_stream = discover_controllers("_namib_controller._tcp")?
        .try_filter_map(|addr| try_connect(addr.into(), "_controller._namib", identity.clone(), ca.clone()))
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

pub(crate) async fn heartbeat(
    enforcer_state: Arc<EnforcerState>,
    client: Arc<Mutex<RPCClient>>,
    fw_service: Arc<FirewallService>,
) {
    loop {
        {
            let mut instance = client.lock().await;
            let heartbeat: io::Result<Option<FirewallConfig>> = instance
                .heartbeat(
                    context::current(),
                    enforcer_state
                        .firewall_cfg
                        .read()
                        .await
                        .as_ref()
                        .map(|c| c.version().into()),
                )
                .await;
            match heartbeat {
                Err(error) => error!("Error during heartbeat: {:?}", error),
                Ok(Some(config)) => {
                    debug!("Received new config {:?}", config);
                    fw_service.apply_new_config(config).await;
                },
                Ok(None) => debug!("Heartbeat OK!"),
            }

            drop(instance);
        }

        sleep(Duration::from_secs(5)).await;
    }
}

async fn try_connect(
    addr: SocketAddr,
    dns_name: &'static str,
    identity: Identity,
    ca: Certificate,
) -> Result<Option<RPCClient>> {
    debug!("trying to connect to address {:?}", addr);

    // ip6 geht anscheinend nicht
    if let SocketAddr::V6(_) = addr {
        return Ok(None);
    }

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
    let transport = serde_transport::new(framed_io, codec()());

    Ok(Some(RPCClient::new(client::Config::default(), transport).spawn()?))
}
