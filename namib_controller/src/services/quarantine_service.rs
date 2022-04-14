// Copyright 2022, Hannes Masuch
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::db::DbConnection;
use crate::error::Result;
use crate::models::{Device, DeviceDbo, QuarantineException, QuarantineExceptionDbo};
use crate::services::{device_service, firewall_configuration_service};

pub async fn get_all_quarantined_devices(pool: &DbConnection) -> Result<Vec<Device>> {
    let devices = sqlx::query_as!(DeviceDbo, "SELECT * FROM devices WHERE q_bit = true")
        .fetch_all(pool)
        .await?;

    Ok(devices.into_iter().map(Device::from).collect())
}

/// Sets the quarantine status of the device with the given ID.
/// Returns whether the device's quarantine status was changed by this.
pub async fn change_quarantine_status_device(id: i64, pool: &DbConnection, status: bool) -> Result<bool> {
    let upd_count = sqlx::query!("UPDATE devices SET q_bit = $1 WHERE id = $2", status, id)
        .execute(pool)
        .await?;

    firewall_configuration_service::update_config_version(pool).await?;

    Ok(upd_count.rows_affected() == 1)
}

pub async fn get_quarantine_exception(id: i64, pool: &DbConnection) -> Result<QuarantineExceptionDbo> {
    let exception = sqlx::query_as!(
        QuarantineExceptionDbo,
        "SELECT * FROM quarantine_exceptions WHERE id = $1",
        id
    )
    .fetch_optional(pool)
    .await?;

    if exception.is_some() {
        Ok(exception.unwrap())
    } else {
        Err(sqlx::error::Error::RowNotFound.into())
    }
}

pub async fn insert_quarantine_exception(
    pool: &DbConnection,
    device_id: i64,
    quarantine_exception: QuarantineException,
) -> Result<i64> {
    let direction = quarantine_exception.direction as i64;

    let result = sqlx::query!(
        "INSERT INTO quarantine_exceptions (exception_target, direction, device_id) values ($1, $2, $3) RETURNING id",
        quarantine_exception.exception_target,
        direction,
        device_id,
    )
    .fetch_one(pool)
    .await?
    .id;

    Ok(result)
}

pub async fn get_quarantine_exceptions_for_device(id: i64, pool: &DbConnection) -> Result<Vec<QuarantineException>> {
    if device_service::find_by_id(id, pool).await.is_err() {
        Err(sqlx::error::Error::RowNotFound.into())
    } else {
        let exceptions = sqlx::query_as!(
            QuarantineExceptionDbo,
            "SELECT * FROM quarantine_exceptions WHERE device_id = $1",
            id,
        )
        .fetch_all(pool)
        .await?;

        Ok(exceptions.into_iter().map(QuarantineException::from).collect())
    }
}

pub async fn remove_quarantine_exception(id: i64, pool: &DbConnection) -> Result<bool> {
    let result = sqlx::query!("DELETE FROM quarantine_exceptions WHERE id = $1", id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() == 1)
}

pub async fn update_quarantine_exception(
    device_id: i64,
    exception: QuarantineException,
    pool: &DbConnection,
) -> Result<bool> {
    let direction = exception.direction as i64;

    let result = sqlx::query!(
        "UPDATE quarantine_exceptions SET exception_target = $1, direction = $2, device_id = $3 WHERE id = $4",
        exception.exception_target,
        direction,
        device_id,
        exception.id,
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected() == 1)
}
