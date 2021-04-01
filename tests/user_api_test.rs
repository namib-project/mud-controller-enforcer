mod lib;
use lib::{assert_get_failure, assert_get_successful, assert_post_failure, assert_post_successful};

use actix_rt::{spawn, Arbiter};
use actix_web::{dev::Service, web::head};
use futures::TryFutureExt;
use log::{debug, info};
use namib_mud_controller::{
    controller::app,
    db::DbConnection,
    error::Result,
    models::User,
    routes::dtos::{DeviceDto, LoginDto, SignupDto, SuccessDto, TokenDto, UpdatePasswordDto, UpdateUserDto},
    services::{role_service::ROLE_ID_ADMIN, user_service},
};
use reqwest::{header::HeaderMap, Client, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;
use std::thread;
use tokio::time::{sleep, Duration};

#[derive(Debug, Deserialize, Clone)]
pub struct UserResult {
    pub id: i64,
    pub username: String,
    pub roles: Vec<String>,
    pub roles_ids: Vec<i64>,
    pub permissions: Vec<String>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_signup() -> Result<()> {
    let mut ctx = lib::IntegrationTestContext::new("test_signup").await;
    let server_addr = ctx.start_test_server().await;
    let (client, _auth_token) = lib::create_authorized_http_client(&server_addr).await;

    let result: UserResult = assert_get_successful(&client, format!("http://{}/users/me", server_addr).as_str()).await;
    info!("{:?}", result);
    assert_eq!(result.username, "admin");
    assert_eq!(result.roles[0], "admin");
    assert_eq!(result.roles.len(), 1);
    assert_eq!(result.roles_ids[0], ROLE_ID_ADMIN);
    assert_eq!(result.roles_ids.len(), 1);
    assert_eq!(result.permissions[0], "**");
    assert_eq!(result.permissions.len(), 1);

    let user_count = sqlx::query!(
        "SELECT COUNT(*) AS count FROM users AS u JOIN users_roles AS r ON u.id = r.user_id WHERE u.username = ? AND r.role_id = ?", 
        "admin", 
        ROLE_ID_ADMIN
    ).fetch_one(&ctx.db_conn).await.unwrap().count;
    assert_eq!(user_count, 1);

    ctx.stop_test_server().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_signup_missing_username() -> Result<()> {
    let mut ctx = lib::IntegrationTestContext::new("test_first_signup_missing_username").await;
    let server_addr = ctx.start_test_server().await;
    let client = reqwest::Client::new();

    let signup_dto = json!({
        "password": "password"
    });
    assert_post_failure(
        &client,
        format!("http://{}/users/signup", server_addr).as_str(),
        &signup_dto,
        StatusCode::BAD_REQUEST,
    )
    .await;

    let user_count = sqlx::query!("SELECT COUNT(*) AS count FROM users")
        .fetch_one(&ctx.db_conn)
        .await
        .unwrap()
        .count;
    assert_eq!(user_count, 0);

    ctx.stop_test_server().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_signup_missing_password() -> Result<()> {
    let mut ctx = lib::IntegrationTestContext::new("test_first_signup_missing_password").await;
    let server_addr = ctx.start_test_server().await;
    let client = reqwest::Client::new();

    let signup_dto = json!({
        "username": "admin"
    });
    assert_post_failure(
        &client,
        format!("http://{}/users/signup", server_addr).as_str(),
        &signup_dto,
        StatusCode::BAD_REQUEST,
    )
    .await;

    let user_count = sqlx::query!("SELECT COUNT(*) AS count FROM users")
        .fetch_one(&ctx.db_conn)
        .await
        .unwrap()
        .count;
    assert_eq!(user_count, 0);

    ctx.stop_test_server().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_signup_already_created() -> Result<()> {
    let mut ctx = lib::IntegrationTestContext::new("test_first_signup_wrong_state").await;
    let server_addr = ctx.start_test_server().await;
    let (client, _auth_token) = lib::create_authorized_http_client(&server_addr).await;

    let signup_dto = json!({
        "username": "admin2",
        "password": "password2"
    });
    assert_post_failure(
        &client,
        format!("http://{}/users/signup", server_addr).as_str(),
        &signup_dto,
        StatusCode::BAD_REQUEST,
    )
    .await;

    let user_count = sqlx::query!("SELECT COUNT(*) AS count FROM users WHERE username = ?", "admin2")
        .fetch_one(&ctx.db_conn)
        .await
        .unwrap()
        .count;
    assert_eq!(user_count, 0);

    ctx.stop_test_server().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pw_update() -> Result<()> {
    let mut ctx = lib::IntegrationTestContext::new("test_pw_update").await;
    let server_addr = ctx.start_test_server().await;
    let (client, _auth_token) = lib::create_authorized_http_client(&server_addr).await;

    let before_state = sqlx::query!(
        "SELECT password, salt FROM users AS u JOIN users_roles AS r ON u.id = r.user_id WHERE u.username = ?",
        "admin"
    )
    .fetch_one(&ctx.db_conn)
    .await
    .unwrap();

    let pw_update_dto = UpdatePasswordDto {
        old_password: String::from("password"),
        new_password: String::from("new_password"),
    };
    let _result: SuccessDto = assert_post_successful(
        &client,
        format!("http://{}/users/password", server_addr).as_str(),
        &pw_update_dto,
    )
    .await;

    let after_state = sqlx::query!(
        "SELECT password, salt FROM users AS u JOIN users_roles AS r ON u.id = r.user_id WHERE u.username = ?",
        "admin"
    )
    .fetch_one(&ctx.db_conn)
    .await
    .unwrap();

    assert_ne!(before_state.password, after_state.password);
    assert_ne!(before_state.salt, after_state.salt);

    let login_dto = LoginDto {
        username: "admin".to_string(),
        password: "new_password".to_string(),
    };
    let _result: TokenDto = assert_post_successful(
        &client,
        format!("http://{}/users/login", server_addr).as_str(),
        &login_dto,
    )
    .await;

    ctx.stop_test_server().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pw_update_wrong_old_pw() -> Result<()> {
    let mut ctx = lib::IntegrationTestContext::new("test_pw_update_wrong_old_pw").await;
    let server_addr = ctx.start_test_server().await;
    let (client, _auth_token) = lib::create_authorized_http_client(&server_addr).await;

    let before_state = sqlx::query!(
        "SELECT password, salt FROM users AS u JOIN users_roles AS r ON u.id = r.user_id WHERE u.username = ?",
        "admin"
    )
    .fetch_one(&ctx.db_conn)
    .await
    .unwrap();

    let pw_update_dto = UpdatePasswordDto {
        old_password: String::from("password21"),
        new_password: String::from("new_password"),
    };
    assert_post_failure(
        &client,
        format!("http://{}/users/password", server_addr).as_str(),
        &pw_update_dto,
        StatusCode::UNAUTHORIZED,
    )
    .await;

    let after_state = sqlx::query!(
        "SELECT password, salt FROM users AS u JOIN users_roles AS r ON u.id = r.user_id WHERE u.username = ?",
        "admin"
    )
    .fetch_one(&ctx.db_conn)
    .await
    .unwrap();

    assert_eq!(before_state.password, after_state.password);
    assert_eq!(before_state.salt, after_state.salt);

    ctx.stop_test_server().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pw_update_not_logged_in() -> Result<()> {
    let mut ctx = lib::IntegrationTestContext::new("test_pw_update_not_logged_in").await;
    let server_addr = ctx.start_test_server().await;
    lib::create_authorized_http_client(&server_addr).await;
    let client = reqwest::Client::new();

    let before_state = sqlx::query!(
        "SELECT password, salt FROM users AS u JOIN users_roles AS r ON u.id = r.user_id WHERE u.username = ?",
        "admin"
    )
    .fetch_one(&ctx.db_conn)
    .await
    .unwrap();

    let pw_update_dto = UpdatePasswordDto {
        old_password: String::from("password"),
        new_password: String::from("new_password"),
    };
    assert_post_failure(
        &client,
        format!("http://{}/users/password", server_addr).as_str(),
        &pw_update_dto,
        StatusCode::UNAUTHORIZED,
    )
    .await;

    let after_state = sqlx::query!(
        "SELECT password, salt FROM users AS u JOIN users_roles AS r ON u.id = r.user_id WHERE u.username = ?",
        "admin"
    )
    .fetch_one(&ctx.db_conn)
    .await
    .unwrap();

    assert_eq!(before_state.password, after_state.password);
    assert_eq!(before_state.salt, after_state.salt);

    ctx.stop_test_server().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_username_update() -> Result<()> {
    let mut ctx = lib::IntegrationTestContext::new("test_username_update").await;
    let server_addr = ctx.start_test_server().await;
    let (client, _auth_token) = lib::create_authorized_http_client(&server_addr).await;

    let user_update_dto = UpdateUserDto {
        username: Some(String::from("new_admin")),
    };
    let _result: SuccessDto = assert_post_successful(
        &client,
        format!("http://{}/users/me", server_addr).as_str(),
        &user_update_dto,
    )
    .await;

    let old_name_count = sqlx::query!(
        "SELECT COUNT(*) AS count FROM users AS u JOIN users_roles AS r ON u.id = r.user_id WHERE u.username = ?",
        "admin"
    )
    .fetch_one(&ctx.db_conn)
    .await
    .unwrap()
    .count;

    let new_name_count = sqlx::query!(
        "SELECT COUNT(*) AS count FROM users AS u JOIN users_roles AS r ON u.id = r.user_id WHERE u.username = ?",
        "new_admin"
    )
    .fetch_one(&ctx.db_conn)
    .await
    .unwrap()
    .count;

    assert_eq!(old_name_count, 0);
    assert_eq!(new_name_count, 1);

    let login_dto = LoginDto {
        username: "new_admin".to_string(),
        password: "password".to_string(),
    };
    let _result: TokenDto = assert_post_successful(
        &client,
        format!("http://{}/users/login", server_addr).as_str(),
        &login_dto,
    )
    .await;

    ctx.stop_test_server().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_username_update_none() -> Result<()> {
    let mut ctx = lib::IntegrationTestContext::new("test_username_update_none").await;
    let server_addr = ctx.start_test_server().await;
    let (client, _auth_token) = lib::create_authorized_http_client(&server_addr).await;

    let user_update_dto = UpdateUserDto { username: None };
    let _result: SuccessDto = assert_post_successful(
        &client,
        format!("http://{}/users/me", server_addr).as_str(),
        &user_update_dto,
    )
    .await;

    let old_name_count = sqlx::query!(
        "SELECT COUNT(*) AS count FROM users AS u JOIN users_roles AS r ON u.id = r.user_id WHERE u.username = ?",
        "admin"
    )
    .fetch_one(&ctx.db_conn)
    .await
    .unwrap()
    .count;

    assert_eq!(old_name_count, 1);

    let login_dto = LoginDto {
        username: "admin".to_string(),
        password: "password".to_string(),
    };
    let _result: TokenDto = assert_post_successful(
        &client,
        format!("http://{}/users/login", server_addr).as_str(),
        &login_dto,
    )
    .await;

    ctx.stop_test_server().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_token_refresh() -> Result<()> {
    let mut ctx = lib::IntegrationTestContext::new("test_token_refresh").await;
    let server_addr = ctx.start_test_server().await;
    let (client, auth_token) = lib::create_authorized_http_client(&server_addr).await;

    sleep(Duration::from_secs(2)).await;
    let new_token: TokenDto =
        assert_get_successful(&client, format!("http://{}/users/refresh_token", server_addr).as_str()).await;

    assert_ne!(auth_token.token, new_token.token);

    let mut header_map = HeaderMap::new();
    header_map.insert(
        "authorization",
        (String::from("Bearer ") + new_token.token.as_str()).parse().unwrap(),
    );
    let new_client = reqwest::ClientBuilder::new()
        .default_headers(header_map)
        .build()
        .unwrap();

    let result: UserResult =
        assert_get_successful(&new_client, format!("http://{}/users/me", server_addr).as_str()).await;
    info!("{:?}", result);
    assert_eq!(result.username, "admin");

    ctx.stop_test_server().await?;
    Ok(())
}
