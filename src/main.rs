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
    clippy::must_use_candidate
)]

use std::{env, thread, time::Duration};

use actix_cors::Cors;
use actix_ratelimit::{errors::ARError, MemoryStore, MemoryStoreActor, RateLimiter};
use actix_web::{middleware, App, HttpServer};
use dotenv::dotenv;
use namib_mud_controller::{
    db, error::Result, routes, rpc, services::mud_service::mud_profile_service::job_update_outdated_profiles, VERSION,
};
use paperclip::actix::{web, OpenApiExt};

#[actix_web::main]
async fn main() -> Result<()> {
    dotenv().ok();
    env_logger::init();

    log::info!("Starting mud_controller {}", VERSION);

    let conn = db::connect().await?;
    let conn2 = conn.clone();
    let _rpc = thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("could not construct tokio runtime")
            .block_on(rpc::rpc_server::listen(conn2))
            .expect("failed running rpc server");
    });

    /*Starts a new job that updates the expired profiles at regular intervals.*/
    let conn3 = conn.clone();
    let _computation = thread::spawn(move || {
        job_update_outdated_profiles(
            conn3,                        // Given database connection.
            clokwerk::TimeUnits::hour(1), // Interval at which the expired profiles are updated.
            Duration::from_secs(600),     // How long does the thread sleep until next test.
        );
    });

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
                let ip = connection_info.remote_addr().ok_or(ARError::IdentificationError)?;
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
    .run()
    .await?;

    Ok(())
}
