#![feature(proc_macro_hygiene, decl_macro)]
#![warn(clippy::all, clippy::style, clippy::pedantic)]
#![allow(
    dead_code,
    clippy::manual_range_contains,
    clippy::unseparated_literal_suffix,
    clippy::module_name_repetitions,
    clippy::default_trait_access
)]

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
use tokio::runtime;

use crate::{db::DbConnPool, error::Result};

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
        .attach(AdHoc::on_attach("Database Migrations", db::run_db_migrations))
        .attach(AdHoc::on_attach("RPC Server", |rocket| {
            info!("Launching RPC server");
            let pool = rocket.state::<DbConnPool>().expect("could not get db connection pool").clone();
            let td = thread::spawn(move || {
                let rt = runtime::Builder::new_current_thread().enable_all().build().expect("could not construct tokio runtime");
                rt.block_on(rpc::rpc_server::listen(pool));
            });
            Ok(rocket.manage(td))
        }))
        .mount("/users", routes::users_controller::routes())
        .mount("/mud", routes::mud_controller::routes())
        .mount("/", StaticFiles::from("public"))
        .mount(
            "/swagger-ui/",
            make_swagger_ui(&SwaggerUIConfig {
                urls: vec![UrlObject::new("Users", "../users/openapi.json"), UrlObject::new("MUD", "../mud/openapi.json")],
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
