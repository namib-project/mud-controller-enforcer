#![allow(clippy::needless_pass_by_value)]

use crate::{
    auth::AuthToken,
    db::DbConnection,
    error,
    error::Result,
    models::Device,
    routes::dtos::{DeviceCreationUpdateDto, DeviceDto},
    services::{device_service, role_service::permission::Permission},
};
use actix_web::http::StatusCode;
use paperclip::actix::{
    api_v2_operation, web,
    web::{HttpResponse, Json},
};
use std::net::IpAddr;
use validator::Validate;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(get_all_devices));
    cfg.route("", web::post().to(create_device));
    cfg.route("/{ip}", web::get().to(get_device));
    cfg.route("/{ip}", web::put().to(update_device));
    cfg.route("/{ip}", web::delete().to(delete_device));
}

#[api_v2_operation]
async fn get_all_devices(pool: web::Data<DbConnection>, auth: AuthToken) -> Result<Json<Vec<DeviceDto>>> {
    auth.require_permission(Permission::device__list)?;
    auth.require_permission(Permission::device__read)?;

    let devices = device_service::get_all_devices(&pool).await?;
    Ok(Json(devices.into_iter().map(DeviceDto::from).collect()))
}

#[api_v2_operation]
async fn get_device(pool: web::Data<DbConnection>, auth: AuthToken, ip: web::Path<String>) -> Result<Json<DeviceDto>> {
    auth.require_permission(Permission::device__read)?;

    let ip_addr = parse_ip(&ip)?;

    let device = find_device(ip_addr, &pool).await?;

    Ok(Json(DeviceDto::from(device)))
}

#[api_v2_operation]
async fn create_device(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    device_creation_update_dto: Json<DeviceCreationUpdateDto>,
) -> Result<Json<DeviceDto>> {
    auth.require_permission(Permission::device__write)?;

    device_creation_update_dto.validate().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let ip_addr = parse_ip(&device_creation_update_dto.ip_addr)?;

    device_service::insert_device(&device_creation_update_dto.to_device(0, false)?, &pool).await?;

    let created_device = find_device(ip_addr, &pool).await?;

    Ok(Json(DeviceDto::from(created_device)))
}

#[api_v2_operation]
async fn update_device(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    ip: web::Path<String>,
    device_creation_update_dto: Json<DeviceCreationUpdateDto>,
) -> Result<Json<DeviceDto>> {
    auth.require_permission(Permission::device__write)?;

    device_creation_update_dto.validate().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let ip_addr = parse_ip(&ip)?;

    let existing_device = find_device(ip_addr, &pool).await?;

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
    auth.require_permission(Permission::device__delete)?;

    let ip_addr = parse_ip(&ip)?;

    let existing_device = find_device(ip_addr, &pool).await?;

    device_service::delete_device(existing_device.id, &pool).await?;
    Ok(HttpResponse::NoContent().finish())
}

async fn find_device(ip_addr: IpAddr, pool: &DbConnection) -> Result<Device> {
    device_service::find_by_ip(ip_addr, pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: Some("No device with this IP found".to_string()),
        }
        .fail()
    })
}

fn parse_ip(ip: &str) -> Result<IpAddr> {
    ip.parse().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: Some("Invalid IP address".to_string()),
        }
        .fail()
    })
}
