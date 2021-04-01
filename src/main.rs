#![warn(clippy::all, clippy::style, clippy::pedantic)]
#![allow(
    dead_code,
    clippy::manual_range_contains,
    clippy::unseparated_literal_suffix,
    clippy::module_name_repetitions,
    clippy::default_trait_access,
    clippy::similar_names,
    clippy::redundant_else,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::missing_panics_doc
)]

use actix_cors::Cors;
use actix_ratelimit::{errors::ARError, MemoryStore, MemoryStoreActor, RateLimiter};
use actix_web::{middleware, App, HttpServer};
use dotenv::dotenv;
use lazy_static::LazyStatic;
use namib_mud_controller::{
    controller::app,
    db,
    db::DbConnection,
    error::Result,
    routes, rpc_server,
    services::{acme_service, job_service},
    VERSION,
};
use paperclip::actix::{web, OpenApiExt};
use std::{
    env,
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
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

    let (_end_signal_send, end_signal_rec) = tokio::sync::oneshot::channel();
    let actix_task = tokio::task::spawn_blocking(move || {
        app(
            conn,
            end_signal_rec,
            SocketAddrV4::new(
                Ipv4Addr::new(0, 0, 0, 0),
                env::var("HTTP_PORT")
                    .map(|v| v.parse::<u16>().unwrap_or(DEFAULT_HTTP_PORT))
                    .unwrap_or(DEFAULT_HTTP_PORT),
            )
            .into(),
            Some(
                SocketAddrV4::new(
                    Ipv4Addr::new(0, 0, 0, 0),
                    env::var("HTTPS_PORT")
                        .map(|v| v.parse::<u16>().unwrap_or(DEFAULT_HTTPS_PORT))
                        .unwrap_or(DEFAULT_HTTPS_PORT),
                )
                .into(),
            ),
            None,
            None,
        )
    });

    let r = try_join!(rpc_server_task, job_task, actix_task)?;
    r.0?;
    r.2?;
    Ok(())
}
