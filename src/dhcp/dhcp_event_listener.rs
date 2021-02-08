#[cfg(not(unix))]
pub use mock::*;
#[cfg(unix)]
pub use unix::*;

#[cfg(unix)]
mod unix {
    use std::sync::Arc;

    use crate::rpc::rpc_client::current_rpc_context;
    use futures::future::join_all;
    use log::debug;
    use tokio::{
        io::AsyncReadExt,
        net::{UnixListener, UnixStream},
        sync::RwLock,
    };

    use namib_shared::{models::DhcpEvent, Enforcer};

    /// Listens for DHCP events supplied by the dnsmasq hook script and call relevant handle function.
    pub async fn listen_for_dhcp_events(enforcer: Arc<RwLock<Enforcer>>) {
        match std::fs::remove_file("/tmp/namib_dhcp.sock") {
            Ok(_) => Ok(()),
            Err(e) => match e.kind() {
                std::io::ErrorKind::NotFound => Ok(()),
                e => Err(e),
            },
        }
        .expect("Unable to get access to socket file");
        let listener =
            UnixListener::bind("/tmp/namib_dhcp.sock").expect("Could not open socket for DHCP event listener.");
        let mut active_listeners = Vec::new();
        while let Ok((event_stream, _)) = listener.accept().await {
            let enforcer = enforcer.clone();
            active_listeners.push(tokio::spawn(async move {
                handle_dhcp_script_connection(enforcer, event_stream).await;
            }));
        }
        join_all(active_listeners).await;
    }

    async fn handle_dhcp_script_connection(enforcer: Arc<RwLock<Enforcer>>, mut stream: UnixStream) {
        let mut inc_data = Vec::new();
        stream.read_to_end(&mut inc_data).await.unwrap();
        match serde_json::from_slice::<DhcpEvent>(inc_data.as_slice()) {
            Ok(dhcp_event) => {
                debug!("Received DHCP event: {:?}", &dhcp_event);
                let mut enforcer = enforcer.lock().await;
                enforcer
                    .client
                    .dhcp_request(current_rpc_context(), dhcp_event)
                    .await
                    .unwrap();
            },
            Err(e) => {
                warn!("DHCP event was received, but could not be parsed: {}", e);
            },
        }
    }
}

#[cfg(not(unix))]
mod mock {
    use std::sync::Arc;

    use tokio::sync::RwLock;

    use crate::Enforcer;

    pub async fn listen_for_dhcp_events(_: Arc<RwLock<Enforcer>>) {}
}
