#![allow(clippy::needless_pass_by_value)]

use rocket::{http::Status, Route};
use rocket_contrib::json::Json;
use rocket_okapi::{openapi, routes_with_openapi};
use validator::Validate;

use crate::{
    auth::Auth,
    db::DbConn,
    error::{ResponseError, Result},
    models::user_model::User,
    routes::dtos::users_dto::{LoginDto, RolesDto, SignupDto, SuccessDto, TokenDto, UpdatePasswordDto, UpdateUserDto},
    services::user_service,
};

#[openapi]
#[doc = "# Register a new user"]
#[post("/signup", format = "json", data = "<signup_dto>")]
pub fn signup(conn: DbConn, signup_dto: Json<SignupDto>) -> Result<Json<SuccessDto>> {
    signup_dto.validate().or_else(|_| {
        ResponseError {
            status: Status::BadRequest,
            message: None,
        }
        .fail()
    })?;

    let user = User::new(signup_dto.username.clone(), signup_dto.password.as_str())?;

    user_service::insert(user, &*conn)?;

    Ok(Json(SuccessDto { status: String::from("ok") }))
}

#[openapi]
#[doc = "# Login with username and password"]
#[post("/login", format = "json", data = "<login_dto>")]
pub fn login(conn: DbConn, login_dto: Json<LoginDto>) -> Result<Json<TokenDto>> {
    login_dto.validate().or_else(|_| {
        ResponseError {
            status: Status::BadRequest,
            message: None,
        }
        .fail()
    })?;

    let user = user_service::find_by_username(login_dto.username.as_ref(), &*conn).or_else(|_| {
        ResponseError {
            status: Status::Unauthorized,
            message: None,
        }
        .fail()
    })?;

    User::verify_password(&user, login_dto.password.as_ref()).or_else(|_| {
        ResponseError {
            status: Status::Unauthorized,
            message: None,
        }
        .fail()
    })?;

    Ok(Json(TokenDto {
        token: Auth::encode_token(&Auth::generate_auth(user.id, user.username, "api".to_string())),
    }))
}

#[openapi]
#[doc = "# Retrieve information about the logged-in user"]
#[get("/me")]
pub fn get_me(conn: DbConn, auth: Auth) -> Result<Json<User>> {
    let user = user_service::find_by_id(auth.id, &*conn)?;

    Ok(Json(user))
}

#[openapi]
#[doc = "# Update the current user"]
#[post("/me", format = "json", data = "<update_user_dto>")]
pub fn update_me(conn: DbConn, auth: Auth, update_user_dto: Json<UpdateUserDto>) -> Result<Json<SuccessDto>> {
    update_user_dto.validate().or_else(|_| {
        ResponseError {
            status: Status::BadRequest,
            message: None,
        }
        .fail()
    })?;

    let mut user = user_service::find_by_id(auth.id, &*conn)?;

    if let Some(username) = &update_user_dto.username {
        user.username = username.clone();
    }

    user_service::update(user.id, &user, &*conn)?;

    Ok(Json(SuccessDto { status: String::from("ok") }))
}

#[openapi]
#[doc = "# Update the user's password"]
#[post("/password", format = "json", data = "<update_password_dto>")]
pub fn update_password(conn: DbConn, auth: Auth, update_password_dto: Json<UpdatePasswordDto>) -> Result<Json<SuccessDto>> {
    update_password_dto.validate().or_else(|_| {
        ResponseError {
            status: Status::BadRequest,
            message: None,
        }
        .fail()
    })?;

    let mut user = user_service::find_by_id(auth.id, &*conn)?;

    User::verify_password(&user, &update_password_dto.old_password).or_else(|_| {
        ResponseError {
            status: Status::Unauthorized,
            message: None,
        }
        .fail()
    })?;

    user.password = User::hash_password(&update_password_dto.new_password, &user.salt)?;

    user_service::update(user.id, &user, &*conn)?;

    Ok(Json(SuccessDto { status: String::from("ok") }))
}

#[openapi]
#[doc = "# Retrieve the user's roles"]
#[get("/roles")]
pub fn get_roles(conn: DbConn, auth: Auth) -> Result<Json<RolesDto>> {
    let user = user_service::find_by_id(auth.id, &*conn)?;

    let roles: Vec<String> = user_service::get_roles(&user, &*conn)?.iter().map(|r| r.name.clone()).collect();

    let permissions = user_service::get_permissions(&user, &*conn).unwrap_or_default();

    Ok(Json(RolesDto { roles, permissions }))
}

pub fn routes() -> Vec<Route> {
    routes_with_openapi![signup, login, get_me, update_me, update_password, get_roles]
}
