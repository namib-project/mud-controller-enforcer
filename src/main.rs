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
    clippy::must_use_candidate
)]

use actix_cors::Cors;
use actix_ratelimit::{MemoryStore, MemoryStoreActor, RateLimiter};
use actix_web::{middleware, App, HttpServer};
use dotenv::dotenv;
use namib_mud_controller::{db, error::Result, routes, rpc, VERSION};
/* Used for OpenApi/Swagger generation under the /swagger-ui url */
use paperclip::actix::{web, OpenApiExt};
use std::{env, time::Duration};

#[actix_web::main]
async fn main() -> Result<()> {
    dotenv().ok();
    env_logger::init();

    log::info!("Starting mud_controller {}", VERSION);

    let conn = db::connect().await?;
    let conn2 = conn.clone();

    actix_rt::spawn(async move {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("could not construct tokio runtime")
            .block_on(rpc::rpc_server::listen(conn2))
            .expect("failed running rpc server");
    });
    let store = MemoryStore::new();
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
            .wrap(
                RateLimiter::new(MemoryStoreActor::from(store.clone()).start())
                    .with_interval(Duration::from_secs(60))
                    .with_max_requests(
                        env::var("RATELIMITER_REQUESTS_PER_MINUTE")
                            .unwrap_or("120".to_string())
                            .parse()
                            .unwrap_or(120),
                    )
                    .with_identifier(|req| {
                        let connection_info = req.connection_info().clone();

                        // Setup optional reverse-proxy measures and strip the port from the IP
                        // Will be changed in v0.4, more info: https://github.com/TerminalWitchcraft/actix-ratelimit/issues/15
                        let ip = match env::var("RATELIMITER_BEHIND_REVERSE_PROXY")
                            .unwrap_or("false".to_string())
                            .as_str()
                        {
                            "true" => connection_info.realip_remote_addr().unwrap(),
                            _ => connection_info.remote_addr().unwrap(),
                        };

                        let ip_parts: Vec<&str> = ip.split(":").collect();
                        Ok(ip_parts[0].to_string())
                    }),
            )
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
    .run()
    .await?;

    Ok(())
}
