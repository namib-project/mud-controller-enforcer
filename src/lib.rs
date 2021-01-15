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

#[macro_use]
extern crate log;
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
pub mod services;
