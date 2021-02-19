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

use std::{thread, time::Duration};

use actix_cors::Cors;
use actix_web::{middleware, App, HttpServer};
use clokwerk::{Scheduler, TimeUnits};
use dotenv::dotenv;
//use namib_mud_controller::services::config_firewall_service::update_config_version;
use paperclip::actix::{web, OpenApiExt};

use namib_mud_controller::{db, error::Result, routes, rpc, VERSION};

/* Used for OpenApi/Swagger generation under the /swagger-ui url */
#[actix_web::main]
async fn main() -> Result<()> {
    dotenv().ok();
    env_logger::init();

    log::info!("Starting mud_controller {}", VERSION);

    let conn = db::connect().await?;
    let conn2 = conn.clone();
    let conn3 = conn.clone();
    actix_rt::spawn(async move {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("could not construct tokio runtime")
            .block_on(rpc::rpc_server::listen(conn2))
            .expect("failed running rpc server");
    });

    let _computation = thread::spawn(move || {
        log::info!("Start scheduler");
        let mut scheduler = Scheduler::new();
        scheduler.every(1.seconds()).run(move || {
            let conn4 = conn3.clone();
            log::info!("Start scheduler every {:?}", 1.seconds());
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("could not construct tokio runtime")
                .block_on(
                    namib_mud_controller::services::mud_service::mud_profile_service::update_outdated_profiles(
                        conn4.clone(),
                    ),
                )
                .expect("failed running scheduler for namib_mud_controller::services::mud_service::mud_profile_service::update_outdated_profiles");
        });
        loop {
            scheduler.run_pending();
            thread::sleep(Duration::from_secs(10));
        }
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
    .run()
    .await?;

    Ok(())
}
