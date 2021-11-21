// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

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
    clippy::option_if_let_else,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use dotenv::dotenv;
use log::{error, warn};
use namib_controller::{
    app::ControllerAppBuilder, app_config::APP_CONFIG, auth::initialize_jwt_secret, db, error::Result, rpc_server,
    services::job_service, VERSION,
};
use tokio::select;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    // IMPORTANT: You MUST NOT perform any database queries in the main.rs file because the sqlx offline mode
    // can only analyse queries in the library.
    dotenv().ok();
    env_logger::init();

    log::info!("Starting mud_controller {}", VERSION);

    let conn = db::connect().await?;
    initialize_jwt_secret(&conn).await?;
    let rpc_server_task = tokio::task::spawn(rpc_server::listen(conn.clone()));

    // Starts a new job that updates the expired profiles at regular intervals.
    let job_task = tokio::task::spawn(job_service::start_jobs(conn.clone()));

    let actix_wrapper = ControllerAppBuilder::default()
        .conn(conn)
        .http_addrs(vec![
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, APP_CONFIG.http_port, 0, 0).into(),
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, APP_CONFIG.http_port).into(),
        ])
        .https_addrs(vec![
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, APP_CONFIG.https_port, 0, 0).into(),
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, APP_CONFIG.https_port).into(),
        ])
        .start()
        .await;

    match actix_wrapper {
        Ok(actix_wrapper) => select! {
            result = rpc_server_task => {
                result?
            },
            result = job_task => {
                Ok(result?)
            },
            result = actix_wrapper => {
                result?
            }
        },
        Err((e, wrp)) => {
            error!(
                "Error while awaiting actix server start (did the server terminate unexpectedly during start?): {:?}",
                e
            );
            wrp.stop_server().await
        }
    }
}
