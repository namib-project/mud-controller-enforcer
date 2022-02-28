// Copyright 2022, NAMIB Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::db::DbConnection;
use crate::models::DeviceControllerDbo;

pub async fn get_controllers(url: &str, pool: &DbConnection) -> crate::error::Result<Vec<String>> {
    Ok(sqlx::query_as!(
        DeviceControllerDbo,
        "SELECT * FROM device_controllers WHERE url = $1",
        url
    )
    .fetch_all(pool)
    .await?
    .iter()
    .map(|c| c.controller_uri.clone())
    .collect())
}
