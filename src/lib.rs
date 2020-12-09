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

pub mod auth;
pub mod db;
pub mod error;
pub mod models;
pub mod routes;
pub mod rpc;
pub mod schema;
pub mod services;
