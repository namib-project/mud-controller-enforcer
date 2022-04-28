// Copyright 2020-2022, Jasper Wiegratz, Hannes Masuch
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::field_reassign_with_default)]

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct FlowScope {
    pub name: String,
    pub level: Level,
    pub ttl: i64,
    pub starts_at: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[repr(i64)]
pub enum Level {
    Full = 0,
    HeadersOnly = 1,
}
