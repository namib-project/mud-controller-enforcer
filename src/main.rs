#![warn(clippy::all, clippy::pedantic)]
#![allow(
    dead_code,
    clippy::manual_range_contains,
    clippy::unseparated_literal_suffix,
    clippy::module_name_repetitions,
    clippy::default_trait_access,
    clippy::similar_names,
    clippy::redundant_else,
    clippy::must_use_candidate,
    clippy::cast_possible_truncation,
    clippy::option_if_let_else
)]

use std::{
    env,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    ops::DerefMut,
};

use dotenv::dotenv;
use log::{error, warn};
use namib_mud_controller::{
    controller::ControllerAppWrapper, db, error::Result, rpc_server, services::job_service, VERSION,
};
use tokio::try_join;

const DEFAULT_HTTP_PORT: u16 = 8000;
const DEFAULT_HTTPS_PORT: u16 = 9000;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    dotenv().ok();
    env_logger::init();

    log::info!("Starting mud_controller {}", VERSION);

    let conn = db::connect().await?;
    let rpc_server_task = tokio::task::spawn(rpc_server::listen(conn.clone()));

    // Starts a new job that updates the expired profiles at regular intervals.
    let job_task = tokio::task::spawn(job_service::start_jobs(conn.clone()));

    let http_port = env::var("HTTP_PORT")
        .map_err(|e| warn!("Could not get HTTP_PORT environment variable, using default port instead: {:?}", e))
        .ok()
        .and_then(|v| {
            v.parse::<u16>()
                .map_err(|e| {
                    warn!(
                        "Could not parse HTTP_PORT environment variable, using default port instead  (is it a valid port number?): {:?}",
                        e
                    )
                })
                .ok()
        })
        .unwrap_or(DEFAULT_HTTP_PORT);
    let https_port = env::var("HTTPS_PORT")
        .map_err(|e| warn!("Could not get HTTPS_PORT environment variable, using default port instead: {:?}", e))
        .ok()
        .and_then(|v| {
            v.parse::<u16>()
                .map_err(|e| {
                    warn!(
                        "Could not parse HTTPS_PORT environment variable, using default port instead (is it a valid port number?): {:?}",
                        e
                    )
                })
                .ok()
        })
        .unwrap_or(DEFAULT_HTTPS_PORT);

    let http_addrs = vec![
        SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, http_port, 0, 0).into(),
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, http_port).into(),
    ];

    let https_addrs = vec![
        SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, https_port, 0, 0).into(),
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, https_port).into(),
    ];

    let actix_wrapper = ControllerAppWrapper::start_new_server(conn, http_addrs, https_addrs, None).await;

    if let Err((e, wrp)) = actix_wrapper {
        error!(
            "Error while awaiting actix server start (did the server terminate unexpectedly during start?): {:?}",
            e
        );
        return wrp.stop_server().await.unwrap_or_else(|join_err| Err(join_err.into()));
    } else if let Ok(mut actix_wrapper) = actix_wrapper {
        let r = try_join!(rpc_server_task, job_task, actix_wrapper.deref_mut())?;
        r.0?;
        r.2?;
    }
    Ok(())
}
