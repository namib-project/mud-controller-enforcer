use futures::future::join_all;
use log::debug;
use namib_shared::{
    models::DhcpEvent,
    rpc::{RPCClient, RPC},
};
use std::sync::Arc;
use tarpc::context;
use tokio::{
    io::AsyncReadExt,
    net::{UnixListener, UnixStream},
    stream::StreamExt,
    sync::Mutex,
};

/// Listens for DHCP events supplied by the dnsmasq hook script and call relevant handle function.
#[cfg(unix)]
pub(crate) async fn listen_for_dhcp_events(rpc_client: Arc<Mutex<RPCClient>>) {
    match std::fs::remove_file("/tmp/namib_dhcp.sock") {
        Ok(_) => Ok(()),
        Err(e) => match e.kind() {
            std::io::ErrorKind::NotFound => Ok(()),
            e => Err(e),
        },
    }
    .expect("Unable to get access to socket file");
    let mut listener = UnixListener::bind("/tmp/namib_dhcp.sock").expect("Could not open socket for DHCP event listener.");
    let mut active_listeners = Vec::new();
    while let Some(event_stream) = listener.next().await {
        match event_stream {
            Ok(event_stream) => {
                let rpc_client_copy = rpc_client.clone();
                active_listeners.push(tokio::spawn(async move {
                    handle_dhcp_script_connection(rpc_client_copy, event_stream).await;
                }));
            }
            Err(_) => {}
        }
    }
    join_all(active_listeners).await;
}

#[cfg(unix)]
async fn handle_dhcp_script_connection(rpc_client: Arc<Mutex<RPCClient>>, mut stream: UnixStream) {
    let mut inc_data = Vec::new();
    stream.read_to_end(&mut inc_data).await.unwrap();
    match serde_json::from_slice::<DhcpEvent>(inc_data.as_slice()) {
        Ok(dhcp_event) => {
            debug!("Received DHCP event: {:?}", &dhcp_event);
            let mut unlocked_rpc = rpc_client.lock().await;
            unlocked_rpc.dhcp_request(context::current(), dhcp_event).await.unwrap();
        }
        Err(e) => {
            warn!("DHCP event was received, but could not be parsed: {}", e);
        }
    }
}
