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

mod error;
mod routes;
mod services;
mod models;
mod schema;
mod db;
mod auth;
mod rpc;

fn run_server() {
    rocket::ignite()
        .attach(db::DbConn::fairing())
        .attach(AdHoc::on_attach(
            "Database Migrations",
            db::run_db_migrations,
        ))
        .mount("/users", routes::all_routes())
        .mount("/", StaticFiles::from("public"))
        .mount(
            "/swagger-ui/",
            make_swagger_ui(&SwaggerUIConfig {
                urls: vec![UrlObject::new("Users", "../users/openapi.json")],
                ..Default::default()
            }),
        )
        .launch();
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv()?;
    env_logger::init();

    thread::spawn(run_server);

    rpc::rpc_server::listen().await?;

    Ok(())
}
