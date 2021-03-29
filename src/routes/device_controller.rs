#![allow(clippy::needless_pass_by_value)]

use crate::{
    auth::AuthToken,
    db::DbConnection,
    error,
    error::Result,
    models::Device,
    routes::dtos::{DeviceCreationUpdateDto, DeviceDto, GuessDto},
    services::{
        config_service, config_service::ConfigKeys, device_service, neo4jthings_service, role_service::Permission,
    },
};
use actix_web::http::StatusCode;
use futures::{stream, StreamExt, TryStreamExt};
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
    cfg.route("/{ip}/guesses", web::get().to(guess_thing));
}

#[api_v2_operation]
async fn get_all_devices(pool: web::Data<DbConnection>, auth: AuthToken) -> Result<Json<Vec<DeviceDto>>> {
    auth.require_permission(Permission::device__list)?;
    auth.require_permission(Permission::device__read)?;

    let devices = device_service::get_all_devices(&pool).await?;
    Ok(Json(
        stream::iter(devices)
            .then(|d| d.load_refs(&pool))
            .map_ok(DeviceDto::from)
            .try_collect()
            .await?,
    ))
}

#[api_v2_operation]
async fn get_device(pool: web::Data<DbConnection>, auth: AuthToken, ip: web::Path<String>) -> Result<Json<DeviceDto>> {
    auth.require_permission(Permission::device__read)?;

    let device = find_device(&ip, &pool).await?;

    Ok(Json(DeviceDto::from(device.load_refs(&pool).await?)))
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

    let collect_info = device_creation_update_dto.mud_url.is_none()
        && config_service::get_config_value(ConfigKeys::CollectDeviceData.as_ref(), &pool)
            .await
            .unwrap_or(false);
    let device = device_creation_update_dto.into_inner().into_device(collect_info)?;
    device_service::insert_device(&device, &pool).await?;

    let created_device = find_device(&device.ip_addr.to_string(), &pool).await?;

    Ok(Json(DeviceDto::from(created_device.load_refs(&pool).await?)))
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

    let existing_device = find_device(&ip, &pool).await?;

    let mud_url_from_guess = device_creation_update_dto.mud_url_from_guess.unwrap_or(false);

    let updated_device = device_creation_update_dto
        .into_inner()
        .merge(existing_device)
        .or_else(|_| {
            error::ResponseError {
                status: StatusCode::BAD_REQUEST,
                message: Some("Invalid IP/MAC address in update body specified".to_string()),
            }
            .fail()
        })?;
    device_service::update_device(&updated_device, &pool).await?;

    // if the mud_url was chosen from the guesses, notify the neo4jthings service
    if mud_url_from_guess && updated_device.mud_url.is_some() {
        let mac_addr = updated_device.mac_addr.map(|m| m.to_string()).unwrap();
        let mud_url = updated_device.mud_url.clone().unwrap();
        tokio::spawn(neo4jthings_service::describe_thing(mac_addr, mud_url));
    }

    Ok(Json(DeviceDto::from(updated_device.load_refs(&pool).await?)))
}

#[api_v2_operation]
async fn delete_device(pool: web::Data<DbConnection>, auth: AuthToken, ip: web::Path<String>) -> Result<HttpResponse> {
    auth.require_permission(Permission::device__delete)?;

    let existing_device = find_device(&ip, &pool).await?;

    device_service::delete_device(existing_device.id, &pool).await?;
    Ok(HttpResponse::NoContent().finish())
}

#[api_v2_operation(summary = "Retrieve the MUD-URL guesses for a device")]
async fn guess_thing(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    ip: web::Path<String>,
) -> Result<Json<Vec<GuessDto>>> {
    auth.require_permission(Permission::device__read)?;

    let device = find_device(&ip, &pool).await?;

    let guesses = neo4jthings_service::guess_thing(device).await?;

    Ok(Json(guesses))
}

/// Helper method for finding a device with a given ip, or returning a 404 error if not found.
async fn find_device(ip_addr: &str, pool: &DbConnection) -> Result<Device> {
    device_service::find_by_ip(parse_ip(ip_addr)?, pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: Some("No device with this IP found".to_string()),
        }
        .fail()
    })
}

/// Helper method for parsing a given ip address string into the corresponding struct
fn parse_ip(ip: &str) -> Result<IpAddr> {
    ip.parse().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: Some("Invalid IP address".to_string()),
        }
        .fail()
    })
}
