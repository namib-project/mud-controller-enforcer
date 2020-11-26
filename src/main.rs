#![warn(clippy::all, clippy::style, clippy::pedantic)]
#![allow(dead_code, clippy::module_name_repetitions)]

#[macro_use]
extern crate log;

use std::{net::IpAddr, sync::Arc};

use dotenv::dotenv;
use namib_shared::{models::DHCPRequestData, rpc::RPCClient};
use tarpc::context;
use tokio::sync::Mutex;

use error::Result;

mod dhcp;
mod error;
mod rpc;
mod services;
mod uci;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    dotenv()?;
    env_logger::init();

    let client: Arc<Mutex<RPCClient>> = Arc::new(Mutex::new(rpc::rpc_client::run().await?));
    info!("Connected to RPC server");

    {
        let mut instance = client.lock().await;
        instance
            .dhcp_request(
                context::current(),
                DHCPRequestData {
                    ip_addr: IpAddr::from([127, 0, 0, 1]), // you can also use from_str
                    mac_addr: [1, 2, 3, 4, 5, 6, 7, 8],    // some mac address as u8 array
                    mud_url: "https://url.to/mud/file".to_string(),
                    hostname: "any hostname".to_string(),
                    vendor_class: "some vendor class".to_string(),
                    request_timestamp: std::time::SystemTime::now(),
                },
            )
            .await?;
    }

    let heartbeat_task = rpc::rpc_client::heartbeat(client);

    let dhcp_event_task = dhcp::dhcp_event_listener::listen_for_dhcp_events();

    tokio::join!(heartbeat_task, dhcp_event_task);
    Ok(())
}
