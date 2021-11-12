// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

#![warn(clippy::all, clippy::pedantic)]
#![allow(
    dead_code,
    clippy::manual_range_contains,
    clippy::unseparated_literal_suffix,
    clippy::module_name_repetitions,
    clippy::default_trait_access,
    clippy::similar_names,
    clippy::redundant_else,
    clippy::must_use_candidate,
    clippy::cast_possible_truncation,
    clippy::option_if_let_else,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate validator;

pub mod app;
pub mod app_config;
pub mod auth;
pub mod db;
pub mod error;
pub mod models;
pub mod routes;
pub mod rpc_server;
pub mod services;
pub mod util;

#[cfg(not(debug_assertions))]
const GIT_BRANCH: &str = env!("CI_COMMIT_REF_SLUG");
#[cfg(not(debug_assertions))]
const GIT_COMMIT: &str = env!("CI_COMMIT_SHORT_SHA");
#[cfg(not(debug_assertions))]
pub const VERSION: &str = const_format::concatcp!(GIT_BRANCH, "-", GIT_COMMIT);

#[cfg(debug_assertions)]
pub const VERSION: &str = "development";
