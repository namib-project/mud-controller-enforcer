#![allow(clippy::needless_pass_by_value)]

use isahc::http::StatusCode;
use paperclip::actix::{api_v2_operation, web, web::Json};
use validator::{HasLen, Validate};

use crate::{auth::AuthToken, db::DbConnection, error, error::Result, services::role_service::permission::Permission};

use crate::{
    models::User,
    routes::dtos::{MgmCreateUserDto, MgmRoleInfoDto, MgmUpdateUserBasicDto, MgmUserDto},
    services::{role_service, user_service},
};
use actix_web::HttpResponse;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("/", web::get().to(get_all_users));
    cfg.route("/", web::post().to(create_user));
    cfg.route("/{user_id}", web::get().to(get_user_by_id));
    cfg.route("/{user_id}", web::put().to(update_user_by_id));
    cfg.route("/{user_id}", web::delete().to(delete_user_by_id));
}

#[api_v2_operation(summary = "List of all users")]
pub async fn get_all_users(pool: web::Data<DbConnection>, auth: AuthToken) -> Result<Json<Vec<MgmUserDto>>> {
    auth.require_permission(Permission::user__management__list)?;

    let mut all_users: Vec<MgmUserDto> = vec![];

    for user in user_service::get_all(pool.get_ref()).await?.iter() {
        debug!(">user> {:?}", user);
        all_users.push(MgmUserDto {
            user_id: user.id,
            username: user.username.clone(),
            roles: get_user_roles(user.roles.clone(), user.roles_ids.clone()).await?,
            permissions: user.permissions.clone(),
        });
    }

    Ok(Json(all_users))
}

#[api_v2_operation(summary = "Get a specific user")]
pub async fn get_user_by_id(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    user_id: web::Path<i64>,
) -> Result<Json<MgmUserDto>> {
    auth.require_permission(Permission::user__management__read)?;

    Ok(Json(get_user_from_service(pool.get_ref(), user_id.into_inner()).await?))
}

#[api_v2_operation(summary = "Create a new user")]
pub async fn create_user(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    create_user_dto: Json<MgmCreateUserDto>,
) -> Result<Json<MgmUserDto>> {
    auth.require_permission(Permission::user__management__create)?;

    create_user_dto.validate().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let user = User::new(create_user_dto.username.clone(), create_user_dto.password.as_str())?;
    let new_user_id = user_service::insert(user, pool.get_ref()).await?;

    if auth.require_permission(Permission::role__assign).ok().is_some() {
        for role_id in create_user_dto.roles_ids.iter() {
            role_service::role_add_to_user(pool.get_ref(), new_user_id, *role_id).await?;
        }
    }

    Ok(Json(get_user_from_service(pool.get_ref(), new_user_id).await?))
}

#[api_v2_operation(summary = "Update a user")]
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

    let user_db_result = user_service::find_by_username(&update_user_dto.username, pool.get_ref()).await;
    if user_db_result.is_ok() {
        let same_name_user_db = user_db_result.unwrap();
        if same_name_user_db.id != user_id.clone() {
            return Ok(HttpResponse::Conflict().reason("Username already in use!").finish());
        }
    }

    let mut user_db = user_service::find_by_id(user_id.clone(), pool.get_ref()).await?;
    let mut user = User {
        id: user_id.clone(),
        username: update_user_dto.username.clone(),
        password: user_db.password,
        salt: user_db.salt,
        roles: vec![],
        roles_ids: vec![],
        permissions: vec![],
    };

    user_service::update_username(user_id.clone(), &user, pool.get_ref()).await?;

    if update_user_dto.password.length() > 0 {
        user.password = User::hash_password(&update_user_dto.password, &user.salt)?;
        user_service::update_password(user.id, &user, pool.get_ref()).await?;
    }

    if match auth.require_permission(Permission::role__assign) {
        Ok(_) => true,
        Err(_) => false,
    } {
        for role_id in update_user_dto.roles_ids.iter() {
            if user_db.roles_ids.contains(role_id) {
                match user_db.roles_ids.iter().position(|id| id == role_id) {
                    None => -1,
                    Some(idx) => user_db.roles_ids.remove(idx),
                };
            } else {
                role_service::role_add_to_user(pool.get_ref(), user_id.clone(), *role_id).await?;
            }
        }
    }

    Ok(HttpResponse::NoContent().finish())
}

#[api_v2_operation(summary = "Delete a user")]
pub async fn delete_user_by_id(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    user_id: web::Path<i64>,
) -> Result<HttpResponse> {
    auth.require_permission(Permission::user__management__delete)?;

    user_service::delete(user_id.into_inner(), pool.get_ref()).await?;

    Ok(HttpResponse::NoContent().finish())
}

async fn get_user_from_service(pool: &DbConnection, user_id: i64) -> Result<MgmUserDto> {
    let user = user_service::find_by_id(user_id, pool).await?;

    Ok(MgmUserDto {
        user_id: user.id,
        username: user.username,
        roles: get_user_roles(user.roles, user.roles_ids).await?,
        permissions: user.permissions,
    })
}

async fn get_user_roles(user_roles_names: Vec<String>, user_roles_ids: Vec<i64>) -> Result<Vec<MgmRoleInfoDto>> {
    let mut user_roles: Vec<MgmRoleInfoDto> = vec![];
    let mut i = 0;

    for user_role_name in user_roles_names.iter() {
        user_roles.push(MgmRoleInfoDto {
            id: user_roles_ids[i],
            name: user_role_name.clone(),
        });
        i += 1;
    }

    Ok(user_roles)
}
