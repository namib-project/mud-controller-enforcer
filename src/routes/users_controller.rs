#![allow(clippy::field_reassign_with_default)]

use actix_web::{http::StatusCode, HttpResponse};
use paperclip::actix::{api_v2_operation, web, web::Json};
use snafu::ensure;
use validator::Validate;

use crate::{
    auth::AuthToken,
    db::DbConnection,
    error,
    error::Result,
    models::User,
    routes::dtos::{
        LoginDto, SignupDto, SuccessDto, TokenDto, UpdatePasswordDto, UpdateUserDto, UserConfigDto, UserConfigValueDto,
    },
    services::{config_service, config_service::ConfigKeys, user_config_service, user_service},
};

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("/signup", web::post().to(signup));
    cfg.route("/login", web::post().to(login));
    cfg.route("/refresh_token", web::get().to(refresh_token));
    cfg.route("/me", web::get().to(get_me));
    cfg.route("/me", web::post().to(update_me));
    cfg.route("/password", web::post().to(update_password));
    cfg.route("/configs", web::get().to(get_users_configs));
    cfg.route("/configs/{key}", web::get().to(get_users_config));
    cfg.route("/configs/{key}", web::post().to(set_users_config));
    cfg.route("/configs/{key}", web::delete().to(delete_users_config));
}

#[api_v2_operation(summary = "Register a new user")]
pub async fn signup(pool: web::Data<DbConnection>, signup_dto: Json<SignupDto>) -> Result<Json<SuccessDto>> {
    ensure!(
        config_service::get_config_value(ConfigKeys::AllowUserSignup.as_ref(), &pool)
            .await
            .unwrap_or(false),
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: "Signup is not enabled".to_string(),
        }
    );

    signup_dto.validate().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let user = User::new(signup_dto.0.username, &signup_dto.0.password)?;

    user_service::insert(user, &pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    Ok(Json(SuccessDto {
        status: String::from("ok"),
    }))
}

#[api_v2_operation(summary = "Login with username and password")]
pub async fn login(pool: web::Data<DbConnection>, login_dto: Json<LoginDto>) -> Result<Json<TokenDto>> {
    login_dto.validate().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let user = user_service::find_by_username(&login_dto.username, &pool)
        .await
        .or_else(|_| {
            error::ResponseError {
                status: StatusCode::UNAUTHORIZED,
                message: None,
            }
            .fail()
        })?;

    user.verify_password(&login_dto.password).or_else(|_| {
        error::ResponseError {
            status: StatusCode::UNAUTHORIZED,
            message: None,
        }
        .fail()
    })?;

    user_service::update_last_interaction_stamp(user.id, &pool).await?;

    Ok(Json(TokenDto {
        token: AuthToken::encode_token(&AuthToken::generate_access_token(
            user.id,
            user.username,
            user.permissions,
        )),
    }))
}

#[api_v2_operation(summary = "Refreshes the jwt token if it is not expired.")]
pub async fn refresh_token(pool: web::Data<DbConnection>, auth: AuthToken) -> Result<Json<TokenDto>> {
    let user = user_service::find_by_id(auth.sub, &pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    Ok(Json(TokenDto {
        token: AuthToken::encode_token(&AuthToken::generate_access_token(
            auth.sub,
            user.username,
            user.permissions,
        )),
    }))
}

#[api_v2_operation(summary = "Retrieve information about the logged-in user")]
pub async fn get_me(pool: web::Data<DbConnection>, auth: AuthToken) -> Result<Json<User>> {
    let user = user_service::find_by_id(auth.sub, &pool).await?;

    Ok(Json(user))
}

#[api_v2_operation(summary = "Update the current user")]
pub fn update_me(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    update_user_dto: Json<UpdateUserDto>,
) -> Result<Json<SuccessDto>> {
    update_user_dto.validate().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let mut user = user_service::find_by_id(auth.sub, &pool).await?;

    if let Some(username) = &update_user_dto.username {
        user.username = username.clone();
    }

    user_service::update(&user, &pool).await?;

    Ok(Json(SuccessDto {
        status: String::from("ok"),
    }))
}

#[api_v2_operation(summary = "Update the user's password")]
pub fn update_password(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    update_password_dto: Json<UpdatePasswordDto>,
) -> Result<Json<SuccessDto>> {
    update_password_dto.validate().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let user = user_service::find_by_id(auth.sub, &pool).await?;

    user.verify_password(&update_password_dto.old_password).or_else(|_| {
        error::ResponseError {
            status: StatusCode::UNAUTHORIZED,
            message: None,
        }
        .fail()
    })?;

    user_service::update_password(auth.sub, &update_password_dto.new_password, &pool).await?;

    Ok(Json(SuccessDto {
        status: String::from("ok"),
    }))
}

#[api_v2_operation(summary = "Gets the config variables of the user")]
pub fn get_users_configs(pool: web::Data<DbConnection>, auth: AuthToken) -> Result<Json<Vec<UserConfigDto>>> {
    let user_configs = user_config_service::get_all_configs_for_user(auth.sub, &pool).await?;

    let mut user_configs_dto = vec![];

    for uc in user_configs {
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
    key: web::Path<String>,
    auth: AuthToken,
) -> Result<Json<UserConfigDto>> {
    let user_config_db = user_config_service::get_config_for_user(auth.sub, &key, &pool).await;

    let user_config_db = match user_config_db {
        Ok(user_config) => user_config,
        Err(_) => {
            return error::ResponseError {
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

#[api_v2_operation(summary = "Sets a config variables of the user. Returns status code 204 on success.")]
pub fn set_users_config(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    key: web::Path<String>,
    user_config_value_dto: Json<UserConfigValueDto>,
) -> Result<HttpResponse> {
    user_config_value_dto.validate().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    user_config_service::upsert_config_for_user(auth.sub, &key, &user_config_value_dto.value, &pool).await?;

    Ok(HttpResponse::NoContent().finish())
}

#[api_v2_operation(summary = "Deletes a config variables of the user. Returns status code 204 on success.")]
pub fn delete_users_config(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    key: web::Path<String>,
) -> Result<HttpResponse> {
    user_config_service::delete_config_for_user(auth.sub, &key, &pool).await?;

    Ok(HttpResponse::NoContent().finish())
}
