// Copyright 2022, Matthias Reichmann
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::needless_pass_by_value)]

use actix_web::http::StatusCode;
use paperclip::actix::{
    api_v2_operation, web,
    web::{HttpResponse, Json},
};
use snafu::ensure;
use validator::Validate;

use crate::{
    auth::AuthToken,
    db::DbConnection,
    error,
    error::Result,
    routes::dtos::{RoomDto, FloorCreationUpdateDto, FloorDto},
    services::{role_service::Permission, floor_service},
};

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(get_all_floors));
    cfg.route("/{id}", web::get().to(get_floor));
    cfg.route("/{id}/rooms", web::get().to(get_all_rooms_of_floor));
    cfg.route("", web::post().to(create_floor));
    cfg.route("/{id}", web::put().to(update_floor));
    cfg.route("/{id}", web::delete().to(delete_floor));
}

#[api_v2_operation(summary = "Return all floors.", tags(Floors))]
async fn get_all_floors(pool: web::Data<DbConnection>, auth: AuthToken) -> Result<Json<Vec<FloorDto>>> {
    auth.require_permission(Permission::floor__list)?;
    auth.require_permission(Permission::floor__read)?;
    let res = floor_service::get_all_floors(&pool).await?;
    debug!("{:?}", res);
    Ok(Json(res.into_iter().map(FloorDto::from).collect()))
}

#[api_v2_operation(summary = "Get a floor through the floor id.", tags(Floors))]
async fn get_floor(pool: web::Data<DbConnection>, auth: AuthToken, id: web::Path<i64>) -> Result<Json<FloorDto>> {
    auth.require_permission(Permission::floor__read)?;
    let res = floor_service::find_by_id(id.into_inner(), &pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: Some("Floor can not be found.".to_string()),
        }
        .fail()
    })?;
    debug!("{:?}", res);
    Ok(Json(FloorDto::from(res)))
}

#[api_v2_operation(summary = "Returns all rooms in a floor.", tags(Floors))]
async fn get_all_rooms_of_floor(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    id: web::Path<i64>,
) -> Result<Json<Vec<RoomDto>>> {
    auth.require_permission(Permission::floor__read)?;
    auth.require_permission(Permission::room__list)?;
    auth.require_permission(Permission::room__read)?;

    floor_service::find_by_id(id.0, &pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: Some("Floor can not be found.".to_string()),
        }
        .fail()
    })?;

    let res = floor_service::get_all_rooms_of_floor(id.0, &pool)
        .await
        .or_else(|_| {
            error::ResponseError {
                status: StatusCode::NOT_FOUND,
                message: Some("No rooms found in the floor.".to_string()),
            }
            .fail()
        })?;
    debug!("{:?}", res);
    Ok(Json(
        res.into_iter().map(|r| RoomDto::from(r)).collect()
    ))
}

#[api_v2_operation(summary = "Creates a new floor.", tags(Floors))]
async fn create_floor(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    floor_creation_update_dto: Json<FloorCreationUpdateDto>,
) -> Result<Json<FloorDto>> {
    auth.require_permission(Permission::floor__write)?;

    floor_creation_update_dto.validate().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    if floor_service::find_by_label(&floor_creation_update_dto.label, &pool)
        .await
        .is_ok()
    {
        error::ResponseError {
            status: StatusCode::CONFLICT,
            message: Some("Floor already exists.".to_string()),
        }
        .fail()?;
    }

    let floor = floor_creation_update_dto.into_inner().into_floor(0);
    floor_service::insert_floor(&floor, &pool).await?;
    let res = floor_service::find_by_label(&floor.label, &pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: Some("Could not insert floor.".to_string()),
        }
        .fail()
    })?;
    debug!("{:?}", res);
    Ok(Json(FloorDto::from(res)))
}

#[api_v2_operation(summary = "Updates a floor.", tags(Floors))]
async fn update_floor(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    id: web::Path<i64>,
    floor_creation_update_dto: Json<FloorCreationUpdateDto>,
) -> Result<Json<FloorDto>> {
    auth.require_permission(Permission::floor__write)?;

    floor_creation_update_dto.validate().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let floor = floor_creation_update_dto.into_inner().into_floor(id.0);

    debug!("{:?}", floor);

    if floor_service::find_by_label(&floor.label, &pool)
        .await
        .map_or(id.0, |floor| floor.id)
        != id.0
    {
        error::ResponseError {
            status: StatusCode::CONFLICT,
            message: Some("Floor already exists.".to_string()),
        }
        .fail()?;
    }

    let updated = floor_service::update(&floor, &pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: Some("Could not update floor.".to_string()),
        }
        .fail()
    })?;

    ensure!(
        updated,
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: Some("Floor can not be found.".to_string()),
        }
    );

    Ok(Json(FloorDto::from(floor)))
}

#[api_v2_operation(summary = "Deletes a floor.", tags(Floors))]
async fn delete_floor(pool: web::Data<DbConnection>, auth: AuthToken, id: web::Path<i64>) -> Result<HttpResponse> {
    auth.require_permission(Permission::floor__delete)?;

    let find_floor = floor_service::find_by_id(id.0, &pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: None,
        }
        .fail()
    })?;
    debug!("{:?}", find_floor);
    floor_service::delete_floor(&find_floor.label, &pool).await?;
    Ok(HttpResponse::NoContent().finish())
}
