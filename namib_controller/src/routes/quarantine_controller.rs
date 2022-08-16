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
    services::{device_service, mud_service, quarantine_service, role_service::Permission},
};

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(get_all_quarantined_devices));
    cfg.route("/{id}", web::put().to(quarantine_device));
    cfg.route("/{id}", web::delete().to(remove_device_from_quarantine));
    cfg.route("/exception", web::get().to(get_all_quarantine_exceptions));
    cfg.route("/exception", web::post().to(add_quarantine_exception));
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
    exception_dto: Json<QuarantineExceptionCreationUpdateDto>,
) -> Result<Json<QuarantineExceptionDto>> {
    auth.require_permission(Permission::device__write)?;
    if exception_dto.direction != Some("ToDevice".to_string())
        && exception_dto.direction != Some("FromDevice".to_string())
    {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: Some("Direction must be either ToDevice or FromDevice".to_string()),
        }
        .fail()
    } else if exception_dto.mud_url.is_some() && exception_dto.device_id.is_some()
        || exception_dto.mud_url.is_none() && exception_dto.device_id.is_none()
    {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: Some("Either mud_url or device_id can be set".to_string()),
        }
        .fail()
    } else {
        let device_id = exception_dto.device_id;
        let mud_url = exception_dto.mud_url.clone();
        if exception_dto.device_id.is_some() && device_service::find_by_id(device_id.unwrap(), &pool).await.is_err() {
            error::ResponseError {
                status: StatusCode::BAD_REQUEST,
                message: Some("No device with this ID found".to_string()),
            }
            .fail()
        } else if exception_dto.mud_url.is_some()
            && mud_service::get_mud(mud_url.unwrap().as_str(), &pool).await.is_none()
        {
            error::ResponseError {
                status: StatusCode::BAD_REQUEST,
                message: Some("No device with this mud_url found".to_string()),
            }
            .fail()
        } else {
            let mud_url = exception_dto.mud_url.clone();
            let mut exception = QuarantineException::from(exception_dto.into_inner());
            exception.id =
                quarantine_service::insert_quarantine_exception(&pool, device_id, mud_url.clone(), exception.clone())
                    .await?;
            Ok(Json(exception.into_dto(device_id, mud_url)))
        }
    }
}

#[api_v2_operation(summary = "List all exceptions")]
async fn get_all_quarantine_exceptions(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
) -> Result<Json<Vec<QuarantineExceptionDto>>> {
    auth.require_permission(Permission::device__list)?;
    auth.require_permission(Permission::device__read)?;

    let result = quarantine_service::get_all_quarantine_exceptions(&pool).await?;

    Ok(Json(result.into_iter().map(QuarantineExceptionDto::from).collect()))
}

#[api_v2_operation(summary = "List all exception of device with id")]
async fn get_all_exceptions_for_device(
    pool: web::Data<DbConnection>,
    id: web::Path<i64>,
    auth: AuthToken,
) -> Result<Json<Vec<QuarantineExceptionDto>>> {
    auth.require_permission(Permission::device__list)?;
    auth.require_permission(Permission::device__read)?;
    let mud_url = device_service::find_by_id(*id, &pool).await?.mud_url;

    let result = quarantine_service::get_quarantine_exceptions_for_device(Some(*id), mud_url.clone(), &pool).await;

    if let Ok(exception) = result {
        Ok(Json(exception.into_iter().map(QuarantineExceptionDto::from).collect()))
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
            Some(id) => Some(id),
            None => exception_dbo.device_id,
        };
        let mud_url = match exception_dto.mud_url.clone() {
            Some(mud_url) => Some(mud_url),
            None => exception_dbo.mud_url.clone(),
        };
        if mud_url.is_some() && device_id.is_some() {
            error::ResponseError {
                status: StatusCode::BAD_REQUEST,
                message: Some("Bad Input".to_string()),
            }
            .fail()
        } else {
            let mut exception = QuarantineException::from(exception_dbo);

            exception_dto.into_inner().apply(&mut exception);
            quarantine_service::update_quarantine_exception(device_id, mud_url.clone(), exception.clone(), &pool)
                .await?;

            Ok(Json(exception.into_dto(device_id, mud_url)))
        }
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
