// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

#![warn(clippy::all, clippy::style, clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::default_trait_access)]

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use tokio_serde::formats::Cbor;

use crate::firewall_config::FirewallDevice;

pub mod firewall_config;
pub mod flow_scope;
pub mod macaddr;
pub mod models;
pub mod rpc;

pub use tarpc;

/// Returns the codec used for RPC communication
pub fn codec<Item, SinkItem>() -> Cbor<Item, SinkItem> {
    Cbor::default()
}

/// Stores a set of firewall rules and a config version
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EnforcerConfig {
    version: String,
    devices: Vec<FirewallDevice>,
    secure_name: String,
    expiration_date_time: Option<NaiveDateTime>,
}

impl EnforcerConfig {
    /// Construct a new firewall config with the given version and firewall rules
    pub fn new(
        version: String,
        devices: Vec<FirewallDevice>,
        secure_name: String,
        expiration_date_time: Option<NaiveDateTime>,
    ) -> Self {
        EnforcerConfig {
            version,
            devices,
            secure_name,
            expiration_date_time,
        }
    }

    /// Returns the version of this config
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns a reference to the firewall rules in this config
    pub fn devices(&self) -> &[FirewallDevice] {
        &self.devices
    }

    /// Returns the secure dns name of the enforcer's controller
    pub fn secure_name(&self) -> &str {
        &self.secure_name
    }

    /// Returns the expiration date time of this config, based on the ttl of the active flow scopes
    pub fn expiration_date_time(&self) -> Option<NaiveDateTime> {
        self.expiration_date_time
    }
}
