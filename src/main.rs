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
};

use dotenv::dotenv;
use namib_mud_controller::{controller::app, db, error::Result, rpc_server, services::job_service, VERSION};
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

    let (_end_signal_send, end_signal_rec) = tokio::sync::oneshot::channel();
    let actix_task = tokio::task::spawn_blocking(move || {
        app(
            conn,
            end_signal_rec,
            vec![
                SocketAddrV4::new(
                    Ipv4Addr::new(0, 0, 0, 0),
                    env::var("HTTP_PORT")
                        .map(|v| v.parse::<u16>().unwrap_or(DEFAULT_HTTP_PORT))
                        .unwrap_or(DEFAULT_HTTP_PORT),
                )
                .into(),
                SocketAddrV6::new(
                    Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
                    env::var("HTTP_PORT")
                        .map(|v| v.parse::<u16>().unwrap_or(DEFAULT_HTTPS_PORT))
                        .unwrap_or(DEFAULT_HTTPS_PORT),
                    0,
                    0,
                )
                .into(),
            ],
            vec![
                SocketAddrV4::new(
                    Ipv4Addr::new(0, 0, 0, 0),
                    env::var("HTTPS_PORT")
                        .map(|v| v.parse::<u16>().unwrap_or(DEFAULT_HTTPS_PORT))
                        .unwrap_or(DEFAULT_HTTPS_PORT),
                )
                .into(),
                SocketAddrV6::new(
                    Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
                    env::var("HTTPS_PORT")
                        .map(|v| v.parse::<u16>().unwrap_or(DEFAULT_HTTPS_PORT))
                        .unwrap_or(DEFAULT_HTTPS_PORT),
                    0,
                    0,
                )
                .into(),
            ],
            None,
            None,
        )
    });

    let r = try_join!(rpc_server_task, job_task, actix_task)?;
    r.0?;
    r.2?;
    Ok(())
}
