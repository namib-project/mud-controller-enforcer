#![allow(clippy::needless_pass_by_value)]

use crate::{
    auth::AuthToken,
    db::DbConnection,
    error,
    error::Result,
    models::Device,
    routes::dtos::{DeviceCreationUpdateDto, DeviceDto, GuessDto},
    services::{
        config_service, config_service::ConfigKeys, device_service, neo4things_service, role_service::Permission,
    },
};
use actix_web::http::StatusCode;
use futures::{stream, StreamExt, TryStreamExt};
use paperclip::actix::{
    api_v2_operation, web,
    web::{HttpResponse, Json},
};
use validator::Validate;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(get_all_devices));
    cfg.route("", web::post().to(create_device));
    cfg.route("/{id}", web::get().to(get_device));
    cfg.route("/{id}", web::put().to(update_device));
    cfg.route("/{id}", web::delete().to(delete_device));
    cfg.route("/{id}/guesses", web::get().to(guess_thing));
}

#[api_v2_operation(summary = "List all devices")]
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

#[api_v2_operation(summary = "Get a device by id")]
async fn get_device(pool: web::Data<DbConnection>, auth: AuthToken, id: web::Path<i64>) -> Result<Json<DeviceDto>> {
    auth.require_permission(Permission::device__read)?;

    let device = find_device(id.into_inner(), &pool).await?;

    Ok(Json(DeviceDto::from(device.load_refs(&pool).await?)))
}

#[api_v2_operation(summary = "Create a device")]
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

    let device = device_creation_update_dto
        .into_inner()
        .into_device(device_creation_update_dto.mud_url.is_none())?;
    let id = device_service::insert_device(&device.load_refs(&pool).await?, &pool).await?;

    let created_device = find_device(id, &pool).await?;
    Ok(Json(DeviceDto::from(created_device.load_refs(&pool).await?)))
}

#[api_v2_operation(summary = "Update a device")]
async fn update_device(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    id: web::Path<i64>,
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

    let mut device = find_device(id.into_inner(), &pool).await?;

    let mud_url_from_guess = device_creation_update_dto.mud_url_from_guess.unwrap_or(false);

    device_creation_update_dto.into_inner().apply_to(&mut device);

    let device_with_refs = device.load_refs(&pool).await?;

    device_service::update_device(&device_with_refs, &pool).await?;

    // if the mud_url was chosen from the guesses, notify the neo4jthings service
    if mud_url_from_guess && device_with_refs.mud_url.is_some() {
        let mac_or_duid = device_with_refs.mac_or_duid();
        let mud_url = device_with_refs.mud_url.clone().unwrap();
        tokio::spawn(neo4things_service::describe_thing(mac_or_duid, mud_url));
    }

    Ok(Json(DeviceDto::from(device_with_refs)))
}

#[api_v2_operation(summary = "Delete a devices")]
async fn delete_device(pool: web::Data<DbConnection>, auth: AuthToken, id: web::Path<i64>) -> Result<HttpResponse> {
    auth.require_permission(Permission::device__delete)?;

    let existing_device = find_device(id.into_inner(), &pool).await?;

    device_service::delete_device(existing_device.id, &pool).await?;
    Ok(HttpResponse::NoContent().finish())
}

#[api_v2_operation(summary = "Retrieve the MUD-Url guesses for a device")]
async fn guess_thing(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    id: web::Path<i64>,
) -> Result<Json<Vec<GuessDto>>> {
    auth.require_permission(Permission::device__read)?;

    let device = find_device(id.into_inner(), &pool).await?;

    let guesses = neo4things_service::guess_thing(device).await?;

    Ok(Json(guesses))
}

/// Helper method for finding a device with a given ip, or returning a 404 error if not found.
async fn find_device(id: i64, pool: &DbConnection) -> Result<Device> {
    device_service::find_by_id(id, pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: Some("No device with this Id found".to_string()),
        }
        .fail()
    })
}
