// Copyright 2022, Jasper Wiegratz, Hannes Masuch
// SPDX-License-Identifier: MIT OR Apache-2.0

use chrono::{Duration, NaiveDateTime};

#[derive(Validate, Debug, Serialize, Deserialize)]
pub struct FlowScopeDbo {
    pub id: i64,
    #[validate(length(max = 50))]
    pub name: String,
    pub level: i64,
    #[validate(range(min = 0))]
    pub ttl: i64,
    pub starts_at: NaiveDateTime,
}

impl From<FlowScopeDbo> for FlowScope {
    fn from(flowscope: FlowScopeDbo) -> Self {
        FlowScope {
            name: flowscope.name,
            level: match flowscope.level {
                0 => FlowScopeLevel::Full,
                _ => FlowScopeLevel::HeadersOnly,
            },
            ttl: flowscope.ttl,
            starts_at: flowscope.starts_at,
        }
    }
}

pub trait EndsAt {
    fn ends_at(&self) -> NaiveDateTime;
}

impl EndsAt for FlowScopeDbo {
    fn ends_at(&self) -> NaiveDateTime {
        match self.starts_at.checked_add_signed(Duration::seconds(self.ttl)) {
            Some(ends_at) => ends_at,
            None => panic!("Overflow when adding TTL to flow start"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct FlowScope {
    pub name: String,
    pub level: FlowScopeLevel,
    pub ttl: i64,
    pub starts_at: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[repr(i64)]
pub enum FlowScopeLevel {
    Full = 0,
    HeadersOnly = 1,
}

impl EndsAt for FlowScope {
    fn ends_at(&self) -> NaiveDateTime {
        match self.starts_at.checked_add_signed(Duration::seconds(self.ttl)) {
            Some(ends_at) => ends_at,
            None => panic!("Overflow when adding TTL to flow start"),
        }
    }
}
