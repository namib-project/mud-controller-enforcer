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
}

#[api_v2_operation(summary = "List all anomalies", tags(Anomalies))]
async fn get_all_anomalies(pool: web::Data<DbConnection>, auth: AuthToken) -> Result<Json<Vec<AnomalyDto>>> {
    auth.require_permission(Permission::anomaly__list)?;
    auth.require_permission(Permission::anomaly__read)?;

    Ok(Json(
        anomaly_service::get_all_anomalies(&pool)
            .await?
            .iter()
            .map(AnomalyDto::from)
            .collect(),
    ))
}

#[api_v2_operation(summary = "Get an anomaly through the id", tags(Anomalies))]
async fn get_anomaly(pool: web::Data<DbConnection>, auth: AuthToken, id: web::Path<i64>) -> Result<Json<AnomalyDto>> {
    auth.require_permission(Permission::anomaly__read)?;

    let anomaly = anomaly_service::find_by_id(*id, &pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: Some(format!("Anomaly with Id {} can not be found.", *id)),
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

    Ok(Json(AnomalyDto::from(
        &anomaly_service::insert_anomaly(anomaly_creation_dto.into_inner(), &pool).await?,
    )))
}

#[api_v2_operation(summary = "Delete an anomaly", tags(Anomalies))]
async fn delete_anomaly(pool: web::Data<DbConnection>, auth: AuthToken, id: web::Path<i64>) -> Result<HttpResponse> {
    auth.require_permission(Permission::anomaly__delete)?;

    anomaly_service::delete_anomaly(id.into_inner(), &pool).await?;
    Ok(HttpResponse::NoContent().finish())
}
