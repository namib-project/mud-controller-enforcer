#![warn(clippy::all, clippy::style, clippy::pedantic)]
#![allow(
    dead_code,
    clippy::manual_range_contains,
    clippy::unseparated_literal_suffix,
    clippy::module_name_repetitions,
    clippy::default_trait_access,
    clippy::missing_errors_doc,
    clippy::must_use_candidate
)]

use dotenv::dotenv;
use log::info;
use namib_mud_controller::{db, db::DbConnPool, error::Result, routes, rpc};
use rocket::fairing::AdHoc;
use rocket_contrib::serve::StaticFiles;
use rocket_okapi::swagger_ui::{make_swagger_ui, SwaggerUIConfig, UrlObject};
use std::thread;
use tokio::runtime;

fn run_server() {
    rocket::ignite()
        .attach(db::DbConn::fairing())
        .attach(AdHoc::on_attach("Database Migrations", db::run_rocket_db_migrations))
        .attach(AdHoc::on_attach("RPC Server", |rocket| {
            info!("Launching RPC server");
            let pool = rocket.state::<DbConnPool>().expect("could not get db connection pool").clone();
            let td = thread::spawn(move || {
                let rt = runtime::Builder::new_current_thread().enable_all().build().expect("could not construct tokio runtime");
                rt.block_on(rpc::rpc_server::listen(pool)).expect("failed to run rpc server");
            });
            Ok(rocket.manage(td))
        }))
        .mount("/users", routes::users_controller::routes())
        .mount("/devices", routes::device_controller::routes())
        .mount("/mud", routes::mud_controller::routes())
        .mount("/", StaticFiles::from("public"))
        .mount(
            "/swagger-ui/",
            make_swagger_ui(&SwaggerUIConfig {
                urls: vec![
                    UrlObject::new("Users", "../users/openapi.json"),
                    UrlObject::new("MUD", "../mud/openapi.json"),
                    UrlObject::new("Devices", "../devices/openapi.json"),
                ],
                ..Default::default()
            }),
        )
        .launch();
}

fn main() -> Result<()> {
    dotenv()?;
    env_logger::init();

    run_server();

    Ok(())
}
