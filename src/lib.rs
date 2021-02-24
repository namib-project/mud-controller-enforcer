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

#[cfg(not(debug_assertions))]
const GIT_BRANCH: &str = env!("CI_COMMIT_REF_SLUG");
#[cfg(not(debug_assertions))]
const GIT_COMMIT: &str = env!("CI_COMMIT_SHORT_SHA");
#[cfg(not(debug_assertions))]
pub const VERSION: &str = const_format::concatcp!(GIT_BRANCH, "-", GIT_COMMIT);

#[cfg(debug_assertions)]
pub const VERSION: &str = "development";
