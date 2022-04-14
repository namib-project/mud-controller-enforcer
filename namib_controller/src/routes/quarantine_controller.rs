// Copyright 2022, Hannes Masuch
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::needless_pass_by_value)]

use actix_web::http::StatusCode;
use futures::{stream, StreamExt, TryStreamExt};
use paperclip::actix::{api_v2_operation, web, web::HttpResponse, web::Json};

use crate::{
    auth::AuthToken,
    db::DbConnection,
    error::{self, Result},
    models::QuarantineException,
    routes::device_controller,
    routes::dtos::{DeviceDto, QuarantineExceptionCreationUpdateDto, QuarantineExceptionDto},
    services::{device_service, quarantine_service, role_service::Permission},
};

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(get_all_quarantined_devices));
    cfg.route("/{id}", web::put().to(quarantine_device));
    cfg.route("/{id}", web::delete().to(remove_device_from_quarantine));
    cfg.route(
        "/exception/devices/{device_id}",
        web::post().to(add_quarantine_exception),
    );
    cfg.route(
        "/exception/devices/{device_id}",
        web::get().to(get_all_exceptions_for_device),
    );
    cfg.route("/exception/{id}", web::delete().to(delete_exception));
    cfg.route("/exception/{id}", web::put().to(update_quarantine_exception));
    cfg.route("/exception/{id}", web::get().to(get_quarantine_exception));
}

#[api_v2_operation(summary = "List all quarantined devices", tags(Devices))]
async fn get_all_quarantined_devices(pool: web::Data<DbConnection>, auth: AuthToken) -> Result<Json<Vec<DeviceDto>>> {
    auth.require_permission(Permission::device__list)?;
    auth.require_permission(Permission::device__read)?;

    let devices = quarantine_service::get_all_quarantined_devices(&pool).await?;
    Ok(Json(
        stream::iter(devices)
            .then(|d| d.load_refs(&pool))
            .map_ok(DeviceDto::from)
            .try_collect()
            .await?,
    ))
}

#[api_v2_operation(summary = "Quarantine device")]
async fn quarantine_device(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    id: web::Path<i64>,
) -> Result<Json<DeviceDto>> {
    auth.require_permission(Permission::device__write)?;

    let mut device_with_refs = device_controller::find_device(id.into_inner(), &pool).await?;

    quarantine_service::change_quarantine_status_device(device_with_refs.id, &pool, true).await?;

    device_with_refs.q_bit = true;

    Ok(Json(DeviceDto::from(device_with_refs.load_refs(&pool).await?)))
}

#[api_v2_operation(summary = "Remove device from quarantine")]
async fn remove_device_from_quarantine(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    id: web::Path<i64>,
) -> Result<Json<DeviceDto>> {
    auth.require_permission(Permission::device__write)?;

    let mut device_with_refs = device_controller::find_device(id.into_inner(), &pool).await?;

    quarantine_service::change_quarantine_status_device(device_with_refs.id, &pool, false).await?;

    device_with_refs.q_bit = false;

    Ok(Json(DeviceDto::from(device_with_refs.load_refs(&pool).await?)))
}

#[api_v2_operation(summary = "Add quarantine exception to device")]
async fn add_quarantine_exception(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    device_id: web::Path<i64>,
    exception_dto: Json<QuarantineExceptionCreationUpdateDto>,
) -> Result<Json<QuarantineExceptionDto>> {
    auth.require_permission(Permission::device__write)?;
    if exception_dto.direction != Some("ToDevice".to_string())
        && exception_dto.direction != Some("FromDevice".to_string())
    {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: Some("Direction must be either ToDevice or FromDevice ".to_string()),
        }
        .fail()
    } else if device_service::find_by_id(*device_id, &pool).await.is_ok() {
        let mut exception = QuarantineException::from(exception_dto.into_inner());

        exception.id = quarantine_service::insert_quarantine_exception(&pool, *device_id, exception.clone()).await?;

        Ok(Json(exception.into_dto(device_id.into_inner())))
    } else {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: Some("No device with this ID found".to_string()),
        }
        .fail()
    }
}

#[api_v2_operation(summary = "List all exception of device with id")]
async fn get_all_exceptions_for_device(
    pool: web::Data<DbConnection>,
    id: web::Path<i64>,
    auth: AuthToken,
) -> Result<Json<Vec<QuarantineExceptionDto>>> {
    auth.require_permission(Permission::device__list)?;
    auth.require_permission(Permission::device__read)?;

    let result = quarantine_service::get_quarantine_exceptions_for_device(*id, &pool).await;

    if let Ok(exception) = result {
        Ok(Json(exception.into_iter().map(|e| e.into_dto(*id)).collect()))
    } else {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: Some("No device with this ID found".to_string()),
        }
        .fail()
    }
}

#[api_v2_operation(summary = "Delete exception with id")]
async fn delete_exception(pool: web::Data<DbConnection>, id: web::Path<i64>, auth: AuthToken) -> Result<HttpResponse> {
    auth.require_permission(Permission::device__delete)?;

    if quarantine_service::remove_quarantine_exception(id.into_inner(), &pool).await? {
        Ok(HttpResponse::NoContent().finish())
    } else {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: Some("No exception with this ID found".to_string()),
        }
        .fail()
    }
}

#[api_v2_operation(summary = "Update exception with id")]
async fn update_quarantine_exception(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    id: web::Path<i64>,
    exception_dto: Json<QuarantineExceptionCreationUpdateDto>,
) -> Result<Json<QuarantineExceptionDto>> {
    auth.require_permission(Permission::device__write)?;

    let result = quarantine_service::get_quarantine_exception(*id, &pool).await;
    if let Ok(exception_dbo) = result {
        let device_id = match exception_dto.device_id {
            Some(id) => id,
            None => exception_dbo.device_id,
        };
        let mut exception = QuarantineException::from(exception_dbo);

        exception_dto.into_inner().apply(&mut exception);
        quarantine_service::update_quarantine_exception(device_id, exception.clone(), &pool).await?;

        Ok(Json(exception.into_dto(device_id)))
    } else {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: Some("No exception with this ID found".to_string()),
        }
        .fail()
    }
}

#[api_v2_operation(summary = "Get exception with id")]
async fn get_quarantine_exception(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    id: web::Path<i64>,
) -> Result<Json<QuarantineExceptionDto>> {
    auth.require_permission(Permission::device__list)?;
    auth.require_permission(Permission::device__read)?;

    let result = quarantine_service::get_quarantine_exception(id.into_inner(), &pool).await;
    if let Ok(exception) = result {
        Ok(Json(QuarantineExceptionDto::from(exception)))
    } else {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: Some("No exception with this ID found".to_string()),
        }
        .fail()
    }
}
