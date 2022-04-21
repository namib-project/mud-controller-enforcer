// Copyright 2020-2022, Jasper Wiegratz, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::field_reassign_with_default)]

use chrono::{Duration, NaiveDateTime};
use serde::{Deserialize, Serialize};

use crate::macaddr::SerdeMacAddr;

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct FlowScope {
    pub name: String,
    pub targets: Option<Vec<SerdeMacAddr>>,
    pub level: Level,
    pub ttl: i64,
    pub starts_at: NaiveDateTime,
}

pub trait EndsAt {
    fn ends_at(&self) -> NaiveDateTime;
}

impl EndsAt for FlowScope {
    fn ends_at(&self) -> NaiveDateTime {
        match self.starts_at.checked_add_signed(Duration::seconds(self.ttl)) {
            Some(ends_at) => ends_at,
            None => panic!("Overflow when adding TTL to flow start"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum Level {
    Full,
    HeadersOnly,
}
