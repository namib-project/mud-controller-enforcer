// Copyright 2022, Jasper Wiegratz
// SPDX-License-Identifier: MIT OR Apache-2.0

use chrono::NaiveDateTime;
use namib_shared::flow_scope::Level;

#[derive(Validate, Debug, Serialize, Deserialize)]
pub struct FlowScopeDbo {
    pub id: i64,
    #[validate(length(max = 50))]
    pub name: String,
    pub level: LevelDbo,
    #[validate(range(min = 0))]
    pub ttl: i64,
    pub starts_at: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize, sqlx::Type)]
pub enum LevelDbo {
    Full,
    HeadersOnly,
}

impl From<Level> for LevelDbo {
    fn from(level: Level) -> Self {
        match level {
            Level::Full => LevelDbo::Full,
            Level::HeadersOnly => LevelDbo::HeadersOnly,
        }
    }
}
