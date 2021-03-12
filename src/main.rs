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

        App::new()
            .data(conn.clone())
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .wrap_api()
            .service(web::scope("/status").configure(routes::status_controller::init))
            .service(web::scope("/users").configure(routes::users_controller::init))
            .service(web::scope("/devices").configure(routes::device_controller::init))
            .service(web::scope("/mud").configure(routes::mud_controller::init))
            .service(web::scope("/config").configure(routes::config_controller::init))
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
