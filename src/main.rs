#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate diesel;
#[macro_use]
extern crate diesel_migrations;
#[macro_use]
extern crate log;
#[macro_use]
extern crate rocket;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate validator;

use std::thread;

use dotenv::dotenv;
use rocket::fairing::AdHoc;
use rocket_contrib::serve::StaticFiles;
use rocket_okapi::swagger_ui::{make_swagger_ui, SwaggerUIConfig, UrlObject};

use crate::error::*;

mod auth;
mod db;
mod error;
mod models;
mod routes;
mod rpc;
mod schema;
mod services;

fn run_server() {
    rocket::ignite()
        .attach(db::DbConn::fairing())
        .attach(AdHoc::on_attach(
            "Database Migrations",
            db::run_db_migrations,
        ))
        .mount("/users", routes::users_controller::routes())
        .mount("/mud", routes::mud_controller::routes())
        .mount("/", StaticFiles::from("public"))
        .mount(
            "/swagger-ui/",
            make_swagger_ui(&SwaggerUIConfig {
                urls: vec![
                    UrlObject::new("Users", "../users/openapi.json"),
                    UrlObject::new("MUD", "../mud/openapi.json"),
                ],
                ..Default::default()
            }),
        )
        .launch();
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    dotenv()?;
    env_logger::init();

    thread::spawn(run_server);

    rpc::rpc_server::listen().await?;

    Ok(())
}
