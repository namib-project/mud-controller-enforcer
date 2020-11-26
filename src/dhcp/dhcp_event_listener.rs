use chrono::prelude::*;
use futures::future::join_all;
use log::debug;
use namib_shared::models::DhcpEvent;
use serde::{Deserialize, Serialize, Serializer};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::stream::StreamExt;

/// Listens for DHCP events supplied by the dnsmasq hook script and call relevant handle function.
pub(crate) async fn listen_for_dhcp_events() {
    match std::fs::remove_file("/tmp/namib_dhcp.sock") {
        Ok(v) => Ok(v),
        Err(e) => match e.kind() {
            std::io::ErrorKind::NotFound => Ok(()),
            e => Err(e),
        },
    }
    .expect("Unable to get access to socket file");
    let mut listener = UnixListener::bind("/tmp/namib_dhcp.sock")
        .expect("Could not open socket for DHCP event listener.");
    let mut active_listeners = Vec::new();
    while let Some(event_stream) = listener.next().await {
        match event_stream {
            Ok(event_stream) => {
                active_listeners.push(tokio::spawn(async move {
                    handle_dhcp_script_connection(event_stream).await;
                }));
            }
            Err(e) => {}
        }
    }
    join_all(active_listeners).await;
}

async fn handle_dhcp_script_connection(mut stream: UnixStream) {
    let mut inc_data = Vec::new();
    stream.read_to_end(&mut inc_data).await;
    let dhcp_event: DhcpEvent = serde_json::from_slice(inc_data.as_slice()).unwrap();
    debug!("Received DHCP event: {:?}", &dhcp_event);
    // TODO do something with the received event.
}
