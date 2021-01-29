#![allow(clippy::field_reassign_with_default)]

use validator::Validate;

use crate::{
    auth::{AuthAccess, AuthRefresh},
    db::DbConnection,
    error::{ResponseError, Result},
    models::{ActixDataWrapper, User},
    routes::dtos::{
        LoginDto, LoginResponseDto, RoleDto, SignupDto, SuccessDto, TokenDto, UpdatePasswordDto, UpdateUserDto,
    },
    services::user_service,
};
use isahc::http::StatusCode;
use paperclip::actix::{api_v2_operation, web, web::Json};
use std::sync::Arc;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("/signup", web::post().to(signup));
    cfg.route("/login", web::post().to(login));
    cfg.route("/refresh_access_token", web::get().to(refresh_access_token));
    cfg.route("/me", web::get().to(get_me));
    cfg.route("/me", web::post().to(update_me));
    cfg.route("/password", web::post().to(update_password));
    cfg.route("/roles", web::get().to(get_roles));
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
pub async fn login(data: web::Data<ActixDataWrapper>, login_dto: Json<LoginDto>) -> Result<Json<LoginResponseDto>> {
    login_dto.validate().or_else(|_| {
        ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let user = user_service::find_by_username(login_dto.username.as_ref(), &data.get_ref().pool)
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

    let data_mutex_clone = Arc::clone(&data.get_ref().refresh_tokens);
    let mut hashmap = data_mutex_clone.lock().unwrap();
    let random_refresh_token = generate_random_key();
    let _random_refresh_token_copy = random_refresh_token.clone();

    if let Some(user_refresh_tokens) = hashmap.get_mut(&user.id) {
        user_refresh_tokens.push(random_refresh_token);
    } else {
        let mut user_refresh_tokens: Vec<String> = Vec::new();
        user_refresh_tokens.push(random_refresh_token);
        hashmap.insert(user.id, user_refresh_tokens);
    }

    Ok(Json(LoginResponseDto {
        access_token: TokenDto {
            token: AuthAccess::encode_token(&AuthAccess::generate_access_token(
                user.id,
                user.username,
                user.permissions,
            )),
        },
        refresh_token: TokenDto {
            token: AuthRefresh::encode_token(&AuthRefresh::generate_refresh_token(
                user.id,
                _random_refresh_token_copy,
            )),
        },
    }))
}

#[api_v2_operation(summary = "Refresh the access token with the refresh token as the requests bearer token")]
pub async fn refresh_access_token(data: web::Data<ActixDataWrapper>, auth: AuthRefresh) -> Result<Json<TokenDto>> {
    let data_mutex_clone = Arc::clone(&data.get_ref().refresh_tokens);
    let mut hashmap = data_mutex_clone.lock().unwrap();
    let _random_refresh_token = generate_random_key();
    let mut refresh_failure = false;

    if let Some(user_refresh_tokens) = hashmap.get_mut(&auth.sub) {
        if !user_refresh_tokens.contains(&auth.refresh_token) {
            refresh_failure = true;
        }
    } else {
        refresh_failure = true;
    }

    if refresh_failure {
        return ResponseError {
            status: StatusCode::UNAUTHORIZED,
            message: None,
        }
        .fail();
    }

    let user = user_service::find_by_id(auth.sub, &data.get_ref().pool)
        .await
        .or_else(|_| {
            ResponseError {
                status: StatusCode::UNAUTHORIZED,
                message: None,
            }
            .fail()
        })?;

    Ok(Json(TokenDto {
        token: AuthAccess::encode_token(&AuthAccess::generate_access_token(
            user.id,
            user.username,
            user.permissions,
        )),
    }))
}

#[api_v2_operation(summary = "Retrieve information about the logged-in user")]
pub async fn get_me(pool: web::Data<DbConnection>, auth: AuthAccess) -> Result<Json<User>> {
    let user = user_service::find_by_id(auth.sub, pool.get_ref()).await?;

    Ok(Json(user))
}

#[api_v2_operation(summary = "Update the current user")]
pub fn update_me(
    pool: web::Data<DbConnection>,
    auth: AuthAccess,
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
    auth: AuthAccess,
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
pub fn get_roles(pool: web::Data<DbConnection>, auth: AuthAccess) -> Result<Json<Vec<RoleDto>>> {
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

fn generate_random_key() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789-_)(*&^%$#@!~";
    const PASSWORD_LEN: usize = 256;
    let mut rng = rand::thread_rng();

    return (0..PASSWORD_LEN)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
}
