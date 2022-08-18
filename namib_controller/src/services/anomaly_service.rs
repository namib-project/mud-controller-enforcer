// Copyright 2022, Hannes Masuch
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::models::Notification;
use crate::services::{firewall_configuration_service, notification_service};
use crate::{
    db::DbConnection,
    error::Result,
    models::{Anomaly, AnomalyDbo},
    routes::dtos::AnomalyCreationDto,
    services::device_service,
};

pub async fn get_all_anomalies(pool: &DbConnection) -> Result<Vec<Anomaly>> {
    let anomalies = sqlx::query_as!(AnomalyDbo, "SELECT * FROM anomalies")
        .fetch_all(pool)
        .await?;

    Ok(anomalies.into_iter().map(Anomaly::from).collect())
}

pub async fn get_all_device_anomalies(pool: &DbConnection, id: i64) -> Result<Vec<Anomaly>> {
    let anomalies = sqlx::query_as!(
        AnomalyDbo,
        "SELECT * FROM anomalies WHERE source_id = $1 or destination_id = $1",
        id
    )
    .fetch_all(pool)
    .await?;

    Ok(anomalies.into_iter().map(Anomaly::from).collect())
}

pub async fn change_anomaly_collection_status_for_device(pool: &DbConnection, status: bool, id: i64) -> Result<bool> {
    let upd_count = sqlx::query!("UPDATE devices SET log_anomalies = $1 WHERE id = $2", status, id)
        .execute(pool)
        .await?;

    firewall_configuration_service::update_config_version(pool).await?;

    Ok(upd_count.rows_affected() == 1)
}

pub async fn find_by_id(id: i64, pool: &DbConnection) -> Result<Anomaly> {
    let anomaly = sqlx::query_as!(AnomalyDbo, "SELECT * FROM anomalies WHERE id = $1", id)
        .fetch_one(pool)
        .await?;

    Ok(Anomaly::from(anomaly))
}

pub async fn insert_anomaly(mut anomaly_data: AnomalyCreationDto, pool: &DbConnection) -> Result<Anomaly> {
    if let Ok(source) = device_service::find_by_ip(anomaly_data.source_ip.as_str(), pool).await {
        anomaly_data.source_id = Some(source.id);
    } else {
        anomaly_data.source_id = None;
    }
    if let Ok(destination) = device_service::find_by_ip(anomaly_data.destination_ip.as_str(), pool).await {
        anomaly_data.destination_id = Some(destination.id);
    } else {
        anomaly_data.destination_id = None;
    }
    let source_port = match anomaly_data.source_port {
        Some(source_port) => Option::from(i64::from(source_port)),
        _ => None,
    };
    let destination_port = match anomaly_data.destination_port {
        Some(destination_port) => Option::from(i64::from(destination_port)),
        _ => None,
    };
    let l4protocol = match anomaly_data.l4protocol {
        Some(protocol) => Option::from(i64::from(protocol)),
        _ => None,
    };

    let anomaly = sqlx::query_as!(AnomalyDbo,
        "INSERT INTO anomalies (source_ip, source_port, source_id, destination_ip, destination_port, destination_id, l4protocol) values ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
        anomaly_data.source_ip,
        source_port,
        anomaly_data.source_id,
        anomaly_data.destination_ip,
        destination_port,
        anomaly_data.destination_id,
        l4protocol,
    )
    .fetch_one(pool)
    .await?;

    notification_service::insert_notification(&Notification::from(anomaly.clone()), pool).await?;

    anomaly_data.into_anomaly(anomaly.id, anomaly.date_time_created)
}

pub async fn delete_anomaly(id: i64, pool: &DbConnection) -> Result<bool> {
    let del_count = sqlx::query!("DELETE FROM anomalies WHERE id = $1", id)
        .execute(pool)
        .await?;

    Ok(del_count.rows_affected() == 1)
}
