// Copyright 2022, Hannes Masuch
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    auth::AuthToken,
    db::DbConnection,
    error,
    error::Result,
    routes::dtos::{AnomalyCreationDto, AnomalyDto},
    services::{anomaly_service, role_service::Permission},
};
use actix_web::http::StatusCode;
use paperclip::actix::{
    api_v2_operation, web,
    web::{HttpResponse, Json},
};

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(get_all_anomalies));
    cfg.route("", web::post().to(create_anomaly));
    cfg.route("/{id}", web::get().to(get_anomaly));
    cfg.route("/{id}", web::delete().to(delete_anomaly));
    cfg.route("/device/{id}", web::get().to(get_all_device_anomalies));
}

#[api_v2_operation(summary = "List all anomalies", tags(Anomalies))]
async fn get_all_anomalies(pool: web::Data<DbConnection>, auth: AuthToken) -> Result<Json<Vec<AnomalyDto>>> {
    auth.require_permission(Permission::anomaly__list)?;
    auth.require_permission(Permission::anomaly__read)?;

    let anomalies = anomaly_service::get_all_anomalies(&pool).await?;
    let mut anomalies_dtos: Vec<AnomalyDto> = vec![];

    for anomaly in anomalies {
        anomalies_dtos.push(AnomalyDto::from(&anomaly));
    }

    Ok(Json(anomalies_dtos))
}

#[api_v2_operation(summary = "List all anomalies associated with the device with ID", tags(Anomalies))]
async fn get_all_device_anomalies(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    id: web::Path<i64>,
) -> Result<Json<Vec<AnomalyDto>>> {
    auth.require_permission(Permission::anomaly__list)?;
    auth.require_permission(Permission::anomaly__read)?;

    let anomalies = anomaly_service::get_all_device_anomalies(&pool, id.into_inner()).await?;
    let mut anomalies_device_dtos: Vec<AnomalyDto> = vec![];

    for anomaly in anomalies {
        anomalies_device_dtos.push(AnomalyDto::from(&anomaly));
    }

    Ok(Json(anomalies_device_dtos))
}

#[api_v2_operation(summary = "Get an anomaly through the id", tags(Anomalies))]
async fn get_anomaly(pool: web::Data<DbConnection>, auth: AuthToken, id: web::Path<i64>) -> Result<Json<AnomalyDto>> {
    auth.require_permission(Permission::anomaly__read)?;

    let anomaly = anomaly_service::find_by_id(id.into_inner(), &pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: Some("Anomaly can not be found.".to_string()),
        }
        .fail()
    })?;

    Ok(Json(AnomalyDto::from(&anomaly)))
}

#[api_v2_operation(summary = "Create an anomaly", tags(Anomalies))]
async fn create_anomaly(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    anomaly_creation_dto: Json<AnomalyCreationDto>,
) -> Result<Json<AnomalyDto>> {
    auth.require_permission(Permission::anomaly__write)?;
    let anomaly = anomaly_service::insert_anomaly(anomaly_creation_dto, &pool).await?;

    Ok(Json(AnomalyDto::from(
        &anomaly_service::insert_anomaly(anomaly_creation_dto, &pool).await?,
    )))
}

#[api_v2_operation(summary = "Delete an anomaly", tags(Anomalies))]
async fn delete_anomaly(pool: web::Data<DbConnection>, auth: AuthToken, id: web::Path<i64>) -> Result<HttpResponse> {
    auth.require_permission(Permission::anomaly__delete)?;

    anomaly_service::delete_anomaly(id.into_inner(), &pool).await?;
    Ok(HttpResponse::NoContent().finish())
}
