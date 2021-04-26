#![allow(clippy::needless_pass_by_value)]

use actix_web::{http::StatusCode, HttpResponse};
use paperclip::actix::{api_v2_operation, web, web::Json};
use validator::Validate;

use crate::{
    auth::AuthToken,
    db::DbConnection,
    error,
    error::Result,
    models::User,
    routes::dtos::{MgmCreateUserDto, MgmUpdateUserBasicDto},
    services::{role_service, role_service::Permission, user_service},
};

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("/", web::get().to(get_all_users));
    cfg.route("/", web::post().to(create_user));
    cfg.route("/{user_id}", web::get().to(get_user_by_id));
    cfg.route("/{user_id}", web::put().to(update_user_by_id));
    cfg.route("/{user_id}", web::delete().to(delete_user_by_id));
}

#[api_v2_operation(summary = "List of all users", tags(Management))]
pub async fn get_all_users(pool: web::Data<DbConnection>, auth: AuthToken) -> Result<Json<Vec<User>>> {
    auth.require_permission(Permission::user__management__list)?;

    Ok(Json(user_service::get_all(&pool).await?))
}

#[api_v2_operation(summary = "Get a specific user", tags(Management))]
pub async fn get_user_by_id(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    user_id: web::Path<i64>,
) -> Result<Json<User>> {
    auth.require_permission(Permission::user__management__read)?;

    Ok(Json(user_service::find_by_id(user_id.into_inner(), &pool).await?))
}

#[api_v2_operation(summary = "Create a new user", tags(Management))]
pub async fn create_user(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    create_user_dto: Json<MgmCreateUserDto>,
) -> Result<Json<User>> {
    auth.require_permission(Permission::user__management__create)?;

    create_user_dto.validate().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let dto = create_user_dto.into_inner();
    let user = User::new(dto.username, dto.password.as_str())?;
    let new_user_id = user_service::insert(user, &pool).await?;

    if auth.require_permission(Permission::role__assign).is_ok() {
        for role_id in dto.roles_ids {
            role_service::add_role_to_user(&pool, new_user_id, role_id).await?;
        }
    }

    Ok(Json(user_service::find_by_id(new_user_id, &pool).await?))
}

#[api_v2_operation(summary = "Update a user", tags(Management))]
pub async fn update_user_by_id(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    user_id: web::Path<i64>,
    update_user_dto: Json<MgmUpdateUserBasicDto>,
) -> Result<HttpResponse> {
    auth.require_permission(Permission::user__management__write)?;

    update_user_dto.validate().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    if let Ok(same_name_user_db) = user_service::find_by_username(&update_user_dto.username, &pool).await {
        if same_name_user_db.id != user_id.0 {
            return Ok(HttpResponse::Conflict().reason("Username already in use!").finish());
        }
    }

    let mut user = user_service::find_by_id(user_id.0, &pool).await?;
    user.username = update_user_dto.0.username;
    user.last_interaction = chrono::Utc::now().naive_utc();

    if let Some(password) = update_user_dto.0.password {
        user.update_password(&password)?;
    }

    user_service::update(&user, &pool).await?;

    Ok(HttpResponse::NoContent().finish())
}

#[api_v2_operation(summary = "Delete a user", tags(Management))]
pub async fn delete_user_by_id(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    user_id: web::Path<i64>,
) -> Result<HttpResponse> {
    auth.require_permission(Permission::user__management__delete)?;

    user_service::delete(user_id.into_inner(), &pool).await?;

    Ok(HttpResponse::NoContent().finish())
}
