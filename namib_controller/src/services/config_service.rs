// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::str::FromStr;

use crate::{db::DbConnection, error, error::Result, models::Config};

#[derive(strum::AsRefStr)]
pub enum ConfigKeys {
    CollectDeviceData,
    AllowUserSignup,
    FirewallConfigVersion,
}

/// Gets the config value by key from the database.
pub async fn get_config_value<T: FromStr>(key: &str, pool: &DbConnection) -> Result<T> {
    let entry = sqlx::query_as!(Config, "SELECT * FROM config WHERE key = $1", key)
        .fetch_one(pool)
        .await?;

    T::from_str(&entry.value).map_err(|_| error::FromStrError {}.build())
}

/// Returns all config key-value pairs from database
pub async fn get_all_config_data(pool: &DbConnection) -> Result<Vec<Config>> {
    let data = sqlx::query_as!(Config, "SELECT * FROM config").fetch_all(pool).await?;

    Ok(data)
}

/// Writes the config value by key to the database.
/// Upserts the value by key
pub async fn set_config_value<T: ToString>(key: &str, value: T, pool: &DbConnection) -> Result<()> {
    let val = value.to_string();
    let _ins_count = sqlx::query!(
        "INSERT INTO config VALUES ($1, $2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        key,
        val,
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn delete_config_key(key: &str, pool: &DbConnection) -> Result<bool> {
    let del_count = sqlx::query!("DELETE FROM config WHERE key = $1", key)
        .execute(pool)
        .await?;

    Ok(del_count.rows_affected() == 1)
}
