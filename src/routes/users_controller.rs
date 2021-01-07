#![allow(clippy::needless_pass_by_value)]

use validator::Validate;

use crate::{
    auth::Auth,
    db::ConnectionType,
    error::{ResponseError, Result},
    models::user_model::User,
    routes::dtos::users_dto::{LoginDto, RolesDto, SignupDto, SuccessDto, TokenDto, UpdatePasswordDto, UpdateUserDto},
    services::user_service,
};
use isahc::http::StatusCode;
use paperclip::actix::{api_v2_operation, web, web::Json};

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("/signup", web::post().to(signup));
    cfg.route("/login", web::post().to(login));
    cfg.route("/me", web::get().to(get_me));
    cfg.route("/me", web::post().to(update_me));
    cfg.route("/password", web::post().to(update_password));
    cfg.route("/roles", web::get().to(get_roles));
}

#[api_v2_operation(summary = "Register a new user")]
pub async fn signup(pool: web::Data<ConnectionType>, signup_dto: Json<SignupDto>) -> Result<Json<SuccessDto>> {
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
pub async fn login(pool: web::Data<ConnectionType>, login_dto: Json<LoginDto>) -> Result<Json<TokenDto>> {
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
        token: Auth::encode_token(&Auth::generate_auth(user.id, user.username, "api".to_string())),
    }))
}

#[api_v2_operation(summary = "Retrieve information about the logged-in user")]
pub async fn get_me(pool: web::Data<ConnectionType>, auth: Auth) -> Result<Json<User>> {
    let user = user_service::find_by_id(auth.id, pool.get_ref()).await?;

    Ok(Json(user))
}

#[api_v2_operation(summary = "Update the current user")]
pub fn update_me(
    pool: web::Data<ConnectionType>,
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

    let mut user = user_service::find_by_id(auth.id, pool.get_ref()).await?;

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
    pool: web::Data<ConnectionType>,
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

    let mut user = user_service::find_by_id(auth.id, pool.get_ref()).await?;

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

#[api_v2_operation(summary = "Retrieve the user's roles")]
pub fn get_roles(pool: web::Data<ConnectionType>, auth: Auth) -> Result<Json<RolesDto>> {
    let user = user_service::find_by_id(auth.id, &pool).await?;

    let roles: Vec<String> = user_service::get_roles(&user, &pool)
        .await?
        .iter()
        .map(|r| r.name.clone())
        .collect();

    let permissions = user_service::get_permissions(&user, &pool).await.unwrap_or_default();

    Ok(Json(RolesDto { roles, permissions }))
}
