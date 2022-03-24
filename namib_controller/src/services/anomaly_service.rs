// Copyright 2020-2022, Hannes Masuch
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    db::DbConnection,
    error::Result,
    models::{Anomaly, AnomalyDbo},
    routes::dtos::AnomalyCreationDto,
    services::device_service,
};
use actix_web::web::Json;
use chrono::{Duration, Utc};

pub async fn get_all_anomalies(pool: &DbConnection) -> Result<Vec<Anomaly>> {
    let anomalies = sqlx::query_as!(AnomalyDbo, "SELECT * FROM anomalies")
        .fetch_all(pool)
        .await?;

    Ok(anomalies.into_iter().map(Anomaly::from).collect())
}

pub async fn find_by_id(id: i64, pool: &DbConnection) -> Result<Anomaly> {
    let anomaly = sqlx::query_as!(AnomalyDbo, "SELECT * FROM anomalies WHERE id = $1", id)
        .fetch_one(pool)
        .await?;

    Ok(Anomaly::from(anomaly))
}

pub async fn insert_anomaly(mut anomaly_data: Json<AnomalyCreationDto>, pool: &DbConnection) -> Result<Anomaly> {
    if let Ok(source) = device_service::find_by_ip(anomaly_data.source_ip.as_ref().unwrap().as_str(), pool).await {
        anomaly_data.source_id = Some(source.id);
    } else {
        anomaly_data.source_id = None;
    }
    if let Ok(destination) =
        device_service::find_by_ip(anomaly_data.destination_ip.as_ref().unwrap().as_str(), pool).await
    {
        anomaly_data.destination_id = Some(destination.id);
    } else {
        anomaly_data.destination_id = None;
    }
    if anomaly_data.date_time_created.is_none() {
        anomaly_data.date_time_created = Some(Utc::now().naive_utc() + Duration::hours(1));
    }

    let source_ip_addr = anomaly_data.source_ip.as_ref().unwrap();
    let destination_ip_addr = anomaly_data.destination_ip.as_ref().unwrap();

    let id = sqlx::query!(
        "INSERT INTO anomalies (source_ip, source_port, source_id, destination_ip, destination_port, destination_id, protocol, date_time_created) values ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
        source_ip_addr,
        anomaly_data.source_port,
        anomaly_data.source_id,
        destination_ip_addr,
        anomaly_data.destination_port,
        anomaly_data.destination_id,
        anomaly_data.protocol,
        anomaly_data.date_time_created,
    )
    .fetch_one(pool)
    .await?
    .id;
    anomaly_data.into_anomaly(id)
}

pub async fn delete_anomaly(id: i64, pool: &DbConnection) -> Result<bool> {
    let del_count = sqlx::query!("DELETE FROM anomalies WHERE id = $1", id)
        .execute(pool)
        .await?;

    Ok(del_count.rows_affected() == 1)
}
