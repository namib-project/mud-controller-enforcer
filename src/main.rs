#![warn(clippy::all, clippy::style, clippy::pedantic)]
#![allow(
    dead_code,
    clippy::manual_range_contains,
    clippy::unseparated_literal_suffix,
    clippy::module_name_repetitions,
    clippy::default_trait_access,
    clippy::similar_names,
    clippy::missing_errors_doc,
    clippy::must_use_candidate
)]

use dotenv::dotenv;

use crate::error::Result;
use actix_cors::Cors;
use actix_web::{middleware, App, HttpServer};
use namib_mud_controller::{db, error::Result, routes, rpc};
/* Used for OpenApi/Swagger generation under the /swagger-ui url */
use paperclip::actix::{web, OpenApiExt};

#[actix_web::main]
async fn main() -> Result<()> {
    dotenv().ok();
    env_logger::init();

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
    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .data(conn.clone())
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .wrap_api()
            .service(web::scope("/users").configure(routes::users_controller::init))
            .service(web::scope("/devices").configure(routes::device_controller::init))
            .service(web::scope("/mud").configure(routes::mud_controller::init))
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
