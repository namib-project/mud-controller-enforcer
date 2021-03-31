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
use actix_web::{dev::Service, middleware, App, HttpServer};
use dotenv::dotenv;
use lazy_static::{lazy_static, LazyStatic};
use namib_mud_controller::{
    db,
    db::DbConnection,
    error::Result,
    routes, rpc_server,
    services::{acme_service, job_service},
    VERSION,
};
use paperclip::actix::{web, OpenApiExt};
use std::{env, time::Duration};
use tokio::try_join;

lazy_static! {
    static ref RT: tokio::runtime::Handle = tokio::runtime::Handle::current();
}

fn app(conn: DbConnection) -> Result<()> {
    actix_rt::System::new("main").block_on(async move {
        HttpServer::new(move || {
            let cors = Cors::default()
                .allowed_origin_fn(|origin, _req_head| {
                    origin.as_bytes().starts_with(b"https://localhost:")
                        || origin.as_bytes().starts_with(b"http://localhost:")
                        || origin
                            .as_bytes()
                            .starts_with(format!("https://{}", *acme_service::DOMAIN).as_bytes())
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
                    let ip = if env::var("RATELIMITER_BEHIND_REVERSE_PROXY").as_deref() == Ok("true") {
                        connection_info.realip_remote_addr()
                    } else {
                        connection_info.remote_addr()
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
                .wrap_fn(|req, srv| {
                    let fut = srv.call(req);
                    async {
                        let _hand = RT.enter();
                        fut.await
                    }
                })
                .wrap_api()
                .service(web::scope("/status").configure(routes::status_controller::init))
                .service(web::scope("/users").configure(routes::users_controller::init))
                .service(web::scope("/management/users").configure(routes::users_management_controller::init))
                .service(web::scope("/devices").configure(routes::device_controller::init))
                .service(web::scope("/mud").configure(routes::mud_controller::init))
                .service(web::scope("/config").configure(routes::config_controller::init))
                .service(web::scope("/roles").configure(routes::role_manager_controller::init))
                .service(web::scope("/rooms").configure(routes::room_controller::init))
                .with_json_spec_at("/api/spec")
                .build()
                .service(
                    actix_files::Files::new("/", "static")
                        .index_file("index.html")
                        .redirect_to_slash_directory(),
                )
        })
        .bind(format!(
            "0.0.0.0:{}",
            env::var("HTTP_PORT").unwrap_or_else(|_| "8000".to_string())
        ))?
        .bind_rustls(
            format!(
                "0.0.0.0:{}",
                env::var("HTTPS_PORT").unwrap_or_else(|_| "9000".to_string())
            ),
            acme_service::server_config(),
        )?
        .run()
        .await?;

        Ok(())
    })
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    dotenv().ok();
    env_logger::init();

    log::info!("Starting mud_controller {}", VERSION);

    let conn = db::connect().await?;
    let rpc_server_task = tokio::task::spawn(rpc_server::listen(conn.clone()));

    // Starts a new job that updates the expired profiles at regular intervals.
    let job_task = tokio::task::spawn(job_service::start_jobs(conn.clone()));

    LazyStatic::initialize(&RT);
    let actix_task = tokio::task::spawn_blocking(move || app(conn));

    let r = try_join!(rpc_server_task, job_task, actix_task)?;
    r.0?;
    r.2?;
    Ok(())
}
