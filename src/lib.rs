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
#[cfg(not(debug_assertions))]
#[macro_use]
extern crate dotenv_codegen;

pub mod auth;
pub mod db;
pub mod error;
pub mod models;
pub mod routes;
pub mod rpc;
pub mod services;

#[cfg(not(debug_assertions))]
pub const VERSION: &str = format!("{}_{}", dotenv!("CI_COMMIT_REF_SLUG"), dotenv!("CI_COMMIT_SHORT_SHA"));

#[cfg(debug_assertions)]
pub const VERSION: &str = "development";
