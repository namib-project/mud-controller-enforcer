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
    clippy::must_use_candidate,
    clippy::missing_panics_doc
)]

use actix_cors::Cors;
use actix_ratelimit::{errors::ARError, MemoryStore, MemoryStoreActor, RateLimiter};
use actix_web::{middleware, App, HttpServer};
use dotenv::dotenv;
use namib_mud_controller::{
    db,
    error::Result,
    routes,
    rpc::rpc_server,
    services::{acme_service, job_service},
    VERSION,
};
use paperclip::actix::{web, OpenApiExt};
use std::{env, time::Duration};

#[actix_web::main]
async fn main() -> Result<()> {
    dotenv().ok();
    env_logger::init();

    log::info!("Starting mud_controller {}", VERSION);

    let conn = db::connect().await?;
    let _rpcserver = rpc_server::run_in_tokio(conn.clone());

    // Starts a new job that updates the expired profiles at regular intervals.
    let _jobs = job_service::start_jobs(conn.clone());

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin_fn(|origin, _req_head| {
                origin.as_bytes().starts_with(b"https://localhost:")
                    || origin.as_bytes().starts_with(b"http://localhost:")
            })
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);
        let rate_limiter = RateLimiter::new(MemoryStoreActor::from(MemoryStore::new()).start())
            .with_interval(Duration::from_secs(60))
            .with_max_requests(
                env::var("RATELIMITER_REQUESTS_PER_MINUTE")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(120),
            )
            .with_identifier(|req| {
                let connection_info = req.connection_info();

                // Setup optional reverse-proxy measures and strip the port from the IP
                // Will be changed in v0.4, more info: https://github.com/TerminalWitchcraft/actix-ratelimit/issues/15
                let ip = match env::var("RATELIMITER_BEHIND_REVERSE_PROXY")
                    .unwrap_or("false".to_string())
                    .as_str()
                {
                    "true" => connection_info.realip_remote_addr(),
                    _ => connection_info.remote_addr(),
                }
                .ok_or(ARError::IdentificationError)?;

                let ip_parts: Vec<&str> = ip.split(':').collect();
                Ok(ip_parts[0].to_string())
            });

        App::new()
            .data(conn.clone())
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .wrap(rate_limiter)
            .wrap_api()
            .service(web::scope("/status").configure(routes::status_controller::init))
            .service(web::scope("/users").configure(routes::users_controller::init))
            .service(web::scope("/devices").configure(routes::device_controller::init))
            .service(web::scope("/mud").configure(routes::mud_controller::init))
            .service(web::scope("/config").configure(routes::config_controller::init))
            .service(web::scope("/roles").configure(routes::role_manager_controller::init))
            .with_json_spec_at("/api/spec")
            .build()
            .service(
                actix_files::Files::new("/", "static")
                    .index_file("index.html")
                    .redirect_to_slash_directory(),
            )
    })
    .bind("0.0.0.0:8000")?
    .bind_rustls("0.0.0.0:9000", acme_service::server_config())?
    .run()
    .await?;

    Ok(())
}
