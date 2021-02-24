#![allow(clippy::needless_pass_by_value)]

use crate::{
    auth::AuthToken,
    db::DbConnection,
    error,
    error::Result,
    routes::dtos::{DeviceCreationUpdateDto, DeviceDto},
    services::device_service,
};
use actix_web::http::StatusCode;
use paperclip::actix::{
    api_v2_operation, web,
    web::{HttpResponse, Json},
};
use std::net::IpAddr;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(get_all_devices));
    cfg.route("", web::post().to(create_device));
    cfg.route("/{ip}", web::get().to(get_device));
    cfg.route("/{ip}", web::put().to(update_device));
    cfg.route("/{ip}", web::delete().to(delete_device));
}

#[api_v2_operation]
async fn get_all_devices(pool: web::Data<DbConnection>, auth: AuthToken) -> Result<Json<Vec<DeviceDto>>> {
    auth.require_permission("device/list")?;
    auth.require_permission("device/read")?;

    let devices = device_service::get_all_devices(&pool).await?;
    Ok(Json(devices.into_iter().map(DeviceDto::from).collect()))
}

#[api_v2_operation]
async fn get_device(pool: web::Data<DbConnection>, auth: AuthToken, ip: web::Path<String>) -> Result<Json<DeviceDto>> {
    auth.require_permission("device/read")?;

    let ip_addr = (&ip).parse::<IpAddr>().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: Some("Invalid IP address".to_string()),
        }
        .fail()
    })?;

    let device = device_service::find_by_ip(ip_addr, &pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: Some("No device with this IP found".to_string()),
        }
        .fail()
    })?;

    Ok(Json(DeviceDto::from(device)))
}

#[api_v2_operation]
async fn create_device(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    device_creation_update_dto: Json<DeviceCreationUpdateDto>,
) -> Result<Json<DeviceDto>> {
    auth.require_permission("device/write")?;

    let ip_addr = device_creation_update_dto.ip_addr.parse::<IpAddr>().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: Some("Invalid IP address".to_string()),
        }
        .fail()
    })?;

    device_service::insert_device(&device_creation_update_dto.to_device(0, false)?, &pool).await?;

    let created_device = device_service::find_by_ip(ip_addr, &pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: Some("Couldn't fetch created device.".to_string()),
        }
        .fail()
    })?;

    Ok(Json(DeviceDto::from(created_device)))
}

#[api_v2_operation]
async fn update_device(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    ip: web::Path<String>,
    device_creation_update_dto: Json<DeviceCreationUpdateDto>,
) -> Result<Json<DeviceDto>> {
    auth.require_permission("device/write")?;

    let ip_addr = (&ip).parse::<IpAddr>().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: Some("Invalid IP address".to_string()),
        }
        .fail()
    })?;

    let existing_device = device_service::find_by_ip(ip_addr, &pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: Some("No device with this IP found".to_string()),
        }
        .fail()
    })?;

    let updated_device = device_creation_update_dto
        .to_device(existing_device.id, existing_device.collect_info)
        .or_else(|_| {
            error::ResponseError {
                status: StatusCode::BAD_REQUEST,
                message: Some("Invalid IP/MAC address in update body specified".to_string()),
            }
            .fail()
        })?;
    device_service::update_device(&updated_device, &pool).await?;

    Ok(Json(DeviceDto::from(updated_device)))
}

#[api_v2_operation]
async fn delete_device(pool: web::Data<DbConnection>, auth: AuthToken, ip: web::Path<String>) -> Result<HttpResponse> {
    auth.require_permission("device/delete")?;

    let ip_addr = (&ip).parse::<IpAddr>().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: Some("Invalid IP address".to_string()),
        }
        .fail()
    })?;

    let existing_device = device_service::find_by_ip(ip_addr, &pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: Some("No device with this IP found".to_string()),
        }
        .fail()
    })?;

    device_service::delete_device(existing_device.id, &pool).await?;
    Ok(HttpResponse::NoContent().finish())
}
