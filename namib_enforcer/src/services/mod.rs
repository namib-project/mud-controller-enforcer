// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::env;

pub mod controller_name;
pub mod dns;
pub mod firewall_service;
pub mod log_watcher;
pub mod nflog_watcher;

pub fn is_system_mode() -> bool {
    env::var("NAMIB_SYSTEM").as_deref() == Ok("1")
}

pub fn skip_send_and_process() -> bool {
    env::var("SKIP_SEND_AND_PROCESS").as_deref() == Ok("1")
}
