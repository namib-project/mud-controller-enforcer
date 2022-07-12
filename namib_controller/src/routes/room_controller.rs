// Copyright 2020-2022, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach, Matthias Reichmann
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::needless_pass_by_value)]

use actix_web::http::StatusCode;
use futures::{stream, StreamExt, TryStreamExt};
use paperclip::actix::{api_v2_operation, web, web::Json};
use snafu::ensure;
use validator::Validate;

use crate::{
    auth::AuthToken,
    db::DbConnection,
    error,
    error::Result,
    routes::dtos::{DeviceDto, RoomCreationUpdateDto, RoomDto, RoomGuestUpdateDto},
    services::{role_service::Permission, room_service},
};

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(get_all_rooms));
    cfg.route("/{id}", web::get().to(get_room));
    cfg.route("/{id}/devices", web::get().to(get_all_devices_inside_room));
    cfg.route("", web::post().to(create_room));
    cfg.route("/{id}", web::put().to(update_room));
    cfg.route("/{id}", web::delete().to(delete_room));
    cfg.route("/{id}/guest", web::put().to(change_guest));
}

#[api_v2_operation(summary = "Return all rooms.", tags(Rooms))]
async fn get_all_rooms(pool: web::Data<DbConnection>, auth: AuthToken) -> Result<Json<Vec<RoomDto>>> {
    auth.require_permission(Permission::room__list)?;
    auth.require_permission(Permission::room__read)?;
    let res = room_service::get_all_rooms(&pool).await?;
    debug!("{:?}", res);
    Ok(Json(res.into_iter().map(RoomDto::from).collect()))
}

#[api_v2_operation(summary = "Get a room through the room id.", tags(Rooms))]
async fn get_room(pool: web::Data<DbConnection>, auth: AuthToken, id: web::Path<i64>) -> Result<Json<RoomDto>> {
    auth.require_permission(Permission::room__read)?;
    let res = room_service::find_by_id(id.into_inner(), &pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: Some("Room can not be found.".to_string()),
        }
        .fail()
    })?;
    debug!("{:?}", res);
    Ok(Json(RoomDto::from(res)))
}

#[api_v2_operation(summary = "Returns all devices in a room.", tags(Rooms))]
async fn get_all_devices_inside_room(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    id: web::Path<i64>,
) -> Result<Json<Vec<DeviceDto>>> {
    auth.require_permission(Permission::room__read)?;
    auth.require_permission(Permission::device__list)?;
    auth.require_permission(Permission::device__read)?;

    room_service::find_by_id(id.0, &pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: Some("Room can not be found.".to_string()),
        }
        .fail()
    })?;

    let res = room_service::get_all_devices_inside_room(id.0, &pool)
        .await
        .or_else(|_| {
            error::ResponseError {
                status: StatusCode::NOT_FOUND,
                message: Some("No devices found in the room.".to_string()),
            }
            .fail()
        })?;
    debug!("{:?}", res);
    Ok(Json(
        stream::iter(res)
            .then(|d| d.load_refs(&pool))
            .map_ok(DeviceDto::from)
            .try_collect()
            .await?,
    ))
}

#[api_v2_operation(summary = "Creates a new room. Color in hex e.g. {FFFFFF, 000000}", tags(Rooms))]
async fn create_room(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    room_creation_update_dto: Json<RoomCreationUpdateDto>,
) -> Result<Json<RoomDto>> {
    auth.require_permission(Permission::room__write)?;

    room_creation_update_dto.validate().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    if room_service::find_by_name(&room_creation_update_dto.name, &pool)
        .await
        .is_ok()
    {
        error::ResponseError {
            status: StatusCode::CONFLICT,
            message: Some("Room already exists.".to_string()),
        }
        .fail()?;
    }

    let room = room_creation_update_dto.into_inner().into_room(0);
    room_service::insert_room(&room, &pool).await?;
    let res = room_service::find_by_name(&room.name, &pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: Some("Could not insert room.".to_string()),
        }
        .fail()
    })?;
    debug!("{:?}", res);
    Ok(Json(RoomDto::from(res)))
}

#[api_v2_operation(summary = "Updates a room.", tags(Rooms))]
async fn update_room(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    id: web::Path<i64>,
    room_creation_update_dto: Json<RoomCreationUpdateDto>,
) -> Result<Json<RoomDto>> {
    auth.require_permission(Permission::room__write)?;

    room_creation_update_dto.validate().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let room = room_creation_update_dto.into_inner().into_room(id.0);

    debug!("{:?}", room);

    if room_service::find_by_name(&room.name, &pool)
        .await
        .map_or(id.0, |room| room.room_id)
        != id.0
    {
        return Err(error::invalid_user_input!(
            "A room with this name already exists. Please chose another one or delete the other room first.",
            "name",
            StatusCode::CONFLICT
        ));
    }

    let updated = room_service::update(&room, &pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: Some("Could not update room.".to_string()),
        }
        .fail()
    })?;

    ensure!(
        updated,
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: Some("Room can not be found.".to_string()),
        }
    );

    Ok(Json(RoomDto::from(room)))
}

#[api_v2_operation(summary = "Deletes a room.", tags(Rooms))]
async fn delete_room(pool: web::Data<DbConnection>, auth: AuthToken, id: web::Path<i64>) -> Result<Json<RoomDto>> {
    auth.require_permission(Permission::room__delete)?;

    let find_room = room_service::find_by_id(id.0, &pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: None,
        }
        .fail()
    })?;
    debug!("{:?}", find_room);
    room_service::delete_room(&find_room.name, &pool).await?;
    Ok(Json(RoomDto::from(find_room)))
}

#[api_v2_operation(summary = "Changes the guest in a room.", tags(Rooms))]
async fn change_guest(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    id: web::Path<i64>,
    mut guest_update_dto: Json<RoomGuestUpdateDto>,
) -> Result<Json<RoomDto>> {
    auth.require_permission(Permission::room__write)?;

    guest_update_dto.validate().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let mut find_room = room_service::find_by_id(id.0, &pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: None,
        }
        .fail()
    })?;

    find_room.guest = guest_update_dto.guest.take();

    let updated = room_service::update(&find_room, &pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: Some("Could not update room.".to_string()),
        }
        .fail()
    })?;

    ensure!(
        updated,
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: Some("Room can not be found.".to_string()),
        }
    );

    Ok(Json(RoomDto::from(find_room)))
}
