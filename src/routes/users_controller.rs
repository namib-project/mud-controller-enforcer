#![allow(clippy::field_reassign_with_default)]

use isahc::http::StatusCode;
use paperclip::actix::{api_v2_operation, web, web::Json};
use validator::Validate;

use crate::{
    auth::Auth,
    db::DbConnection,
    error::{ResponseError, Result},
    models::User,
    routes::dtos::{
        LoginDto, RoleDto, SignupDto, SuccessDto, TokenDto, UpdatePasswordDto, UpdateUserDto, UserConfigDto,
        UserConfigRequestDto,
    },
    services::{user_config_service, user_service},
};
use actix_web::HttpResponse;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("/signup", web::post().to(signup));
    cfg.route("/login", web::post().to(login));
    cfg.route("/me", web::get().to(get_me));
    cfg.route("/me", web::post().to(update_me));
    cfg.route("/password", web::post().to(update_password));
    cfg.route("/roles", web::get().to(get_roles));
    cfg.route("/configs", web::get().to(get_users_configs));
    cfg.route("/config", web::get().to(get_users_config));
    cfg.route("/config", web::post().to(set_users_config));
    cfg.route("/config", web::delete().to(delete_users_config));
}

#[api_v2_operation(summary = "Register a new user")]
pub async fn signup(pool: web::Data<DbConnection>, signup_dto: Json<SignupDto>) -> Result<Json<SuccessDto>> {
    signup_dto.validate().or_else(|_| {
        ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let user = User::new(signup_dto.username.clone(), signup_dto.password.as_str())?;

    user_service::insert(user, pool.get_ref()).await?;

    Ok(Json(SuccessDto {
        status: String::from("ok"),
    }))
}

#[api_v2_operation(summary = "Login with username and password")]
pub async fn login(pool: web::Data<DbConnection>, login_dto: Json<LoginDto>) -> Result<Json<TokenDto>> {
    login_dto.validate().or_else(|_| {
        ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let user = user_service::find_by_username(login_dto.username.as_ref(), pool.get_ref())
        .await
        .or_else(|_| {
            ResponseError {
                status: StatusCode::UNAUTHORIZED,
                message: None,
            }
            .fail()
        })?;

    User::verify_password(&user, login_dto.password.as_ref()).or_else(|_| {
        ResponseError {
            status: StatusCode::UNAUTHORIZED,
            message: None,
        }
        .fail()
    })?;

    Ok(Json(TokenDto {
        token: Auth::encode_token(&Auth::generate_auth(user.id, user.username, user.permissions)),
    }))
}

#[api_v2_operation(summary = "Retrieve information about the logged-in user")]
pub async fn get_me(pool: web::Data<DbConnection>, auth: Auth) -> Result<Json<User>> {
    let user = user_service::find_by_id(auth.sub, pool.get_ref()).await?;

    Ok(Json(user))
}

#[api_v2_operation(summary = "Update the current user")]
pub fn update_me(
    pool: web::Data<DbConnection>,
    auth: Auth,
    update_user_dto: Json<UpdateUserDto>,
) -> Result<Json<SuccessDto>> {
    update_user_dto.validate().or_else(|_| {
        ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let mut user = user_service::find_by_id(auth.sub, pool.get_ref()).await?;

    if let Some(username) = &update_user_dto.username {
        user.username = username.clone();
    }

    user_service::update(user.id, &user, pool.get_ref()).await?;

    Ok(Json(SuccessDto {
        status: String::from("ok"),
    }))
}

#[api_v2_operation(summary = "Update the user's password")]
pub fn update_password(
    pool: web::Data<DbConnection>,
    auth: Auth,
    update_password_dto: Json<UpdatePasswordDto>,
) -> Result<Json<SuccessDto>> {
    update_password_dto.validate().or_else(|_| {
        ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let mut user = user_service::find_by_id(auth.sub, pool.get_ref()).await?;

    User::verify_password(&user, &update_password_dto.old_password).or_else(|_| {
        ResponseError {
            status: StatusCode::UNAUTHORIZED,
            message: None,
        }
        .fail()
    })?;

    user.password = User::hash_password(&update_password_dto.new_password, &user.salt)?;

    user_service::update(user.id, &user, pool.get_ref()).await?;

    Ok(Json(SuccessDto {
        status: String::from("ok"),
    }))
}

#[api_v2_operation(summary = "Retrieve all roles")]
pub fn get_roles(pool: web::Data<DbConnection>, auth: Auth) -> Result<Json<Vec<RoleDto>>> {
    auth.require_permission("role/list")?;

    let roles = user_service::get_all_roles(pool.get_ref()).await?;

    Ok(Json(
        roles
            .into_iter()
            .map(|r| RoleDto {
                name: r.name,
                permissions: r.permissions.split(',').map(ToOwned::to_owned).collect(),
            })
            .collect(),
    ))
}

#[api_v2_operation(summary = "Gets the config variables of the user")]
pub fn get_users_configs(pool: web::Data<DbConnection>, auth: Auth) -> Result<Json<Vec<UserConfigDto>>> {
    let user_configs = user_config_service::get_all_configs_for_user(auth.sub, pool.get_ref()).await?;

    let mut user_configs_dto = vec![];

    for uc in user_configs.into_iter() {
        user_configs_dto.push(UserConfigDto {
            key: uc.key,
            value: uc.value,
        });
    }

    Ok(Json(user_configs_dto))
}

#[api_v2_operation(summary = "Gets a config variable of the user")]
pub fn get_users_config(
    pool: web::Data<DbConnection>,
    config: Json<UserConfigRequestDto>,
    auth: Auth,
) -> Result<Json<UserConfigDto>> {
    config.validate().or_else(|_| {
        ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let user_config_db = user_config_service::get_config_for_user(auth.sub, &config.key, pool.get_ref()).await;

    let user_config_db = match user_config_db {
        Ok(user_config) => user_config,
        Err(_) => {
            return ResponseError {
                status: StatusCode::NOT_FOUND,
                message: "Key not found".to_string(),
            }
            .fail()
        },
    };

    Ok(Json(UserConfigDto {
        key: user_config_db.key,
        value: user_config_db.value,
    }))
}

#[api_v2_operation(summary = "Sets a config variables of the user")]
pub fn set_users_config(
    pool: web::Data<DbConnection>,
    auth: Auth,
    user_config_dto: Json<UserConfigDto>,
) -> Result<HttpResponse> {
    user_config_dto.validate().or_else(|_| {
        ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let _insert_result = user_config_service::upsert_config_for_user(
        auth.sub,
        &user_config_dto.key,
        &user_config_dto.value,
        pool.get_ref(),
    )
    .await;

    let _insert_result = match _insert_result {
        Ok(_) => (),
        Err(_) => {
            return ResponseError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: None,
            }
            .fail()
        },
    };

    Ok(HttpResponse::NoContent().finish())
}

#[api_v2_operation(summary = "Deletes a config variables of the user")]
pub fn delete_users_config(
    pool: web::Data<DbConnection>,
    auth: Auth,
    config: Json<UserConfigRequestDto>,
) -> Result<HttpResponse> {
    config.validate().or_else(|_| {
        ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    user_config_service::delete_config_for_user(auth.sub, &config.key, pool.get_ref()).await?;

    Ok(HttpResponse::NoContent().finish())
}
