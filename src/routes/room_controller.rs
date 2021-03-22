#![allow(clippy::needless_pass_by_value)]
use crate::{
    auth::AuthToken,
    db::DbConnection,
    error,
    error::Result,
    routes::dtos::{DeviceDto, RoomCreationUpdateDto, RoomDto},
    services::{role_service::permission::Permission, room_service},
};
use actix_web::http::StatusCode;
use paperclip::actix::{
    api_v2_operation, web,
    web::{HttpResponse, Json},
};
use validator::Validate;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(get_all_rooms));
    cfg.route("/{id}", web::get().to(get_room));
    cfg.route("/{id}/devices", web::get().to(get_all_devices_inside_room));
    cfg.route("", web::post().to(create_room));
    cfg.route("", web::put().to(update_room));
    cfg.route("/{id}", web::delete().to(delete_room));
}

#[api_v2_operation]
async fn get_all_rooms(pool: web::Data<DbConnection>, auth: AuthToken) -> Result<Json<Vec<RoomDto>>> {
    auth.require_permission(Permission::room__list)?;
    auth.require_permission(Permission::room__read)?;
    let res = room_service::get_all_rooms(pool.get_ref()).await?;
    debug!("{:?}", res);
    Ok(Json(res.into_iter().map(RoomDto::from).collect()))
}

#[api_v2_operation]
async fn get_room(pool: web::Data<DbConnection>, auth: AuthToken, id: web::Path<i64>) -> Result<Json<RoomDto>> {
    auth.require_permission(Permission::room__read)?;
    let res = room_service::find_by_id(id.0, pool.get_ref()).await?;
    debug!("{:?}", res);
    Ok(Json(RoomDto::from(res)))
}

#[api_v2_operation]
async fn get_all_devices_inside_room(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    id: web::Path<i64>,
) -> Result<Json<Vec<DeviceDto>>> {
    auth.require_permission(Permission::room__read)?;
    auth.require_permission(Permission::room__list)?;
    auth.require_permission(Permission::device__list)?;
    auth.require_permission(Permission::device__read)?;
    let res = room_service::get_all_devices_inside_room(id.0, pool.get_ref()).await?;
    debug!("{:?}", res);
    Ok(Json(res.into_iter().map(DeviceDto::from).collect()))
}

#[api_v2_operation]
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

    room_service::insert_room(&room_creation_update_dto.to_room(0)?, pool.get_ref()).await?;
    let res = room_service::find_by_name(room_creation_update_dto.name.to_owned(), pool.get_ref()).await?;
    debug!("{:?}", res);
    Ok(Json(RoomDto::from(res)))
}

#[api_v2_operation]
async fn update_room(
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

    let find_room = room_service::find_by_name(room_creation_update_dto.name.clone(), pool.get_ref()).await?;

    room_service::update(&room_creation_update_dto.to_room(find_room.room_id)?, pool.get_ref()).await?;
    debug!("{:?}", find_room);
    Ok(Json(RoomDto::from(find_room)))
}

#[api_v2_operation]
async fn delete_room(pool: web::Data<DbConnection>, auth: AuthToken, id: web::Path<i64>) -> Result<HttpResponse> {
    auth.require_permission(Permission::room__delete)?;

    let find_room = room_service::find_by_id(id.0, &pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: None,
        }
        .fail()
    })?;

    room_service::delete_room(find_room.name, &pool).await?;
    Ok(HttpResponse::NoContent().finish())
}
