mod lib;
use std::thread;

use actix_web::{
    dev::Service,
    rt::{spawn, Arbiter},
    web::head,
};
use futures::TryFutureExt;
use lib::{
    assert_delete_status, assert_get_status, assert_get_status_deserialize, assert_post_status,
    assert_post_status_deserialize,
};
use log::{debug, info};
use namib_mud_controller::{
    controller::app,
    db::DbConnection,
    error::Result,
    models::{Role, User},
    routes::dtos::{
        DeviceDto, LoginDto, SignupDto, StatusDto, SuccessDto, TokenDto, UpdatePasswordDto, UpdateUserDto,
        UserConfigDto, UserConfigValueDto,
    },
    services::{role_service::ROLE_ID_ADMIN, user_service},
};
use reqwest::{header::HeaderMap, Client, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;
use tokio::time::{sleep, Duration};

#[derive(Debug, Deserialize, Clone)]
pub struct UserResult {
    pub id: i64,
    pub username: String,
    pub roles: Vec<Role>,
    pub permissions: Vec<String>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_signup() -> Result<()> {
    let mut ctx = lib::IntegrationTestContext::new("test_signup").await;
    let server_addr = ctx.start_test_server().await;
    let (client, _auth_token) = lib::create_authorized_http_client(&server_addr).await;

    let result: UserResult = assert_get_status_deserialize(
        &client,
        format!("http://{}/users/me", server_addr).as_str(),
        StatusCode::OK,
    )
    .await;
    info!("{:?}", result);
    assert_eq!(result.username, "admin");
    assert_eq!(result.roles[0].name, "admin");
    assert_eq!(result.roles[0].id, ROLE_ID_ADMIN);
    assert_eq!(result.roles.len(), 1);
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
    assert_post_status(
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
    assert_post_status(
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
    assert_post_status(
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
    let _result: SuccessDto = assert_post_status_deserialize(
        &client,
        format!("http://{}/users/password", server_addr).as_str(),
        &pw_update_dto,
        StatusCode::OK,
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
    let _result: TokenDto = assert_post_status_deserialize(
        &client,
        format!("http://{}/users/login", server_addr).as_str(),
        &login_dto,
        StatusCode::OK,
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
    assert_post_status(
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
    assert_post_status(
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
    let _result: SuccessDto = assert_post_status_deserialize(
        &client,
        format!("http://{}/users/me", server_addr).as_str(),
        &user_update_dto,
        StatusCode::OK,
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
    let _result: TokenDto = assert_post_status_deserialize(
        &client,
        format!("http://{}/users/login", server_addr).as_str(),
        &login_dto,
        StatusCode::OK,
    )
    .await;

    ctx.stop_test_server().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_username_update_not_logged_in() -> Result<()> {
    let mut ctx = lib::IntegrationTestContext::new("test_username_update_not_logged_in").await;
    let server_addr = ctx.start_test_server().await;
    let (_client, _auth_token) = lib::create_authorized_http_client(&server_addr).await;
    let client = reqwest::Client::new();

    let user_update_dto = UpdateUserDto {
        username: Some(String::from("new_admin")),
    };
    assert_post_status(
        &client,
        format!("http://{}/users/me", server_addr).as_str(),
        &user_update_dto,
        StatusCode::UNAUTHORIZED,
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
    let _result: SuccessDto = assert_post_status_deserialize(
        &client,
        format!("http://{}/users/me", server_addr).as_str(),
        &user_update_dto,
        StatusCode::OK,
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
    let _result: TokenDto = assert_post_status_deserialize(
        &client,
        format!("http://{}/users/login", server_addr).as_str(),
        &login_dto,
        StatusCode::OK,
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
    let new_token: TokenDto = assert_get_status_deserialize(
        &client,
        format!("http://{}/users/refresh_token", server_addr).as_str(),
        StatusCode::OK,
    )
    .await;

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

    let result: UserResult = assert_get_status_deserialize(
        &new_client,
        format!("http://{}/users/me", server_addr).as_str(),
        StatusCode::OK,
    )
    .await;
    info!("{:?}", result);
    assert_eq!(result.username, "admin");

    ctx.stop_test_server().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_config_empty() -> Result<()> {
    let mut ctx = lib::IntegrationTestContext::new("test_user_config_empty").await;
    let server_addr = ctx.start_test_server().await;
    let (client, _auth_token) = lib::create_authorized_http_client(&server_addr).await;

    let configs: Vec<UserConfigDto> = assert_get_status_deserialize(
        &client,
        format!("http://{}/users/configs", server_addr).as_str(),
        StatusCode::OK,
    )
    .await;

    assert!(configs.is_empty());

    ctx.stop_test_server().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_config_not_logged_in() -> Result<()> {
    let mut ctx = lib::IntegrationTestContext::new("test_user_config_not_logged_in").await;
    let server_addr = ctx.start_test_server().await;
    let (_client, _auth_token) = lib::create_authorized_http_client(&server_addr).await;
    let client = reqwest::Client::new();

    assert_get_status(
        &client,
        format!("http://{}/users/configs", server_addr).as_str(),
        StatusCode::UNAUTHORIZED,
    )
    .await;

    ctx.stop_test_server().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_config_add_single_entry() -> Result<()> {
    let mut ctx = lib::IntegrationTestContext::new("test_user_config_add_single_entry").await;
    let server_addr = ctx.start_test_server().await;
    let (client, _auth_token) = lib::create_authorized_http_client(&server_addr).await;

    let config_entry = UserConfigValueDto {
        value: "testvalue1".to_string(),
    };

    assert_post_status(
        &client,
        format!("http://{}/users/configs/testkey1", server_addr).as_str(),
        &config_entry,
        StatusCode::NO_CONTENT,
    )
    .await;

    let configs: Vec<UserConfigDto> = assert_get_status_deserialize(
        &client,
        format!("http://{}/users/configs", server_addr).as_str(),
        StatusCode::OK,
    )
    .await;

    assert_eq!(configs.len(), 1);
    assert_eq!(configs.get(0).unwrap().key, "testkey1");
    assert_eq!(configs.get(0).unwrap().value, "testvalue1");

    let config: UserConfigDto = assert_get_status_deserialize(
        &client,
        format!("http://{}/users/configs/testkey1", server_addr).as_str(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(config.key, "testkey1");
    assert_eq!(config.value, "testvalue1");

    let db_configs = sqlx::query_as!(
        UserConfigDto,
        "SELECT key, value FROM user_configs AS c JOIN users AS u ON u.id = c.user_id WHERE u.username = ?",
        "admin"
    )
    .fetch_all(&ctx.db_conn)
    .await
    .unwrap();

    assert_eq!(db_configs.len(), 1);
    assert_eq!(db_configs.get(0).unwrap().key, "testkey1");
    assert_eq!(db_configs.get(0).unwrap().value, "testvalue1");

    ctx.stop_test_server().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_config_add_multiple_entries() -> Result<()> {
    let mut ctx = lib::IntegrationTestContext::new("test_user_config_add_multiple_entries").await;
    let server_addr = ctx.start_test_server().await;
    let (client, _auth_token) = lib::create_authorized_http_client(&server_addr).await;

    let config_entry = UserConfigValueDto {
        value: "testvalue1".to_string(),
    };
    let config_entry2 = UserConfigValueDto {
        value: "testvalue2".to_string(),
    };

    assert_post_status(
        &client,
        format!("http://{}/users/configs/testkey1", server_addr).as_str(),
        &config_entry,
        StatusCode::NO_CONTENT,
    )
    .await;

    assert_post_status(
        &client,
        format!("http://{}/users/configs/testkey2", server_addr).as_str(),
        &config_entry2,
        StatusCode::NO_CONTENT,
    )
    .await;

    let configs: Vec<UserConfigDto> = assert_get_status_deserialize(
        &client,
        format!("http://{}/users/configs", server_addr).as_str(),
        StatusCode::OK,
    )
    .await;

    assert_eq!(configs.len(), 2);

    let config: UserConfigDto = assert_get_status_deserialize(
        &client,
        format!("http://{}/users/configs/testkey1", server_addr).as_str(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(config.key, "testkey1");
    assert_eq!(config.value, "testvalue1");

    let db_configs_count = sqlx::query!(
        "SELECT COUNT(*) AS count FROM user_configs AS c JOIN users AS u ON u.id = c.user_id WHERE u.username = ?",
        "admin"
    )
    .fetch_all(&ctx.db_conn)
    .await
    .unwrap();

    let db_config_1 = sqlx::query_as!(
        UserConfigDto,
        "SELECT key, value FROM user_configs AS c JOIN users AS u ON u.id = c.user_id WHERE u.username = ? AND c.key = ?",
        "admin",
        "testkey1"
    )
        .fetch_one(&ctx.db_conn)
        .await
        .unwrap();

    assert_eq!(db_config_1.key, "testkey1");
    assert_eq!(db_config_1.value, "testvalue1");

    let db_config_2 = sqlx::query_as!(
        UserConfigDto,
        "SELECT key, value FROM user_configs AS c JOIN users AS u ON u.id = c.user_id WHERE u.username = ? AND c.key = ?",
        "admin",
        "testkey2"
    )
        .fetch_one(&ctx.db_conn)
        .await
        .unwrap();

    assert_eq!(db_config_2.key, "testkey2");
    assert_eq!(db_config_2.value, "testvalue2");

    ctx.stop_test_server().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_config_update_entry() -> Result<()> {
    let mut ctx = lib::IntegrationTestContext::new("test_user_config_update_single_entry").await;
    let server_addr = ctx.start_test_server().await;
    let (client, _auth_token) = lib::create_authorized_http_client(&server_addr).await;

    let config_entry = UserConfigValueDto {
        value: "testvalue1".to_string(),
    };

    assert_post_status(
        &client,
        format!("http://{}/users/configs/testkey1", server_addr).as_str(),
        &config_entry,
        StatusCode::NO_CONTENT,
    )
    .await;

    let config_entry = UserConfigValueDto {
        value: "testvalue1_new".to_string(),
    };

    assert_post_status(
        &client,
        format!("http://{}/users/configs/testkey1", server_addr).as_str(),
        &config_entry,
        StatusCode::NO_CONTENT,
    )
    .await;

    let configs: Vec<UserConfigDto> = assert_get_status_deserialize(
        &client,
        format!("http://{}/users/configs", server_addr).as_str(),
        StatusCode::OK,
    )
    .await;

    assert_eq!(configs.len(), 1);
    assert_eq!(configs.get(0).unwrap().key, "testkey1");
    assert_eq!(configs.get(0).unwrap().value, "testvalue1_new");

    let config: UserConfigDto = assert_get_status_deserialize(
        &client,
        format!("http://{}/users/configs/testkey1", server_addr).as_str(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(config.key, "testkey1");
    assert_eq!(config.value, "testvalue1_new");

    let db_configs = sqlx::query_as!(
        UserConfigDto,
        "SELECT key, value FROM user_configs AS c JOIN users AS u ON u.id = c.user_id WHERE u.username = ?",
        "admin"
    )
    .fetch_all(&ctx.db_conn)
    .await
    .unwrap();

    assert_eq!(db_configs.len(), 1);
    assert_eq!(db_configs.get(0).unwrap().key, "testkey1");
    assert_eq!(db_configs.get(0).unwrap().value, "testvalue1_new");

    ctx.stop_test_server().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_config_delete_entry() -> Result<()> {
    let mut ctx = lib::IntegrationTestContext::new("test_user_config_delete_entry").await;
    let server_addr = ctx.start_test_server().await;
    let (client, _auth_token) = lib::create_authorized_http_client(&server_addr).await;

    let config_entry = UserConfigValueDto {
        value: "testvalue1".to_string(),
    };

    assert_post_status(
        &client,
        format!("http://{}/users/configs/testkey1", server_addr).as_str(),
        &config_entry,
        StatusCode::NO_CONTENT,
    )
    .await;

    assert_delete_status(
        &client,
        format!("http://{}/users/configs/testkey1", server_addr).as_str(),
        StatusCode::NO_CONTENT,
    )
    .await;

    let configs: Vec<UserConfigDto> = assert_get_status_deserialize(
        &client,
        format!("http://{}/users/configs", server_addr).as_str(),
        StatusCode::OK,
    )
    .await;

    assert_eq!(configs.len(), 0);

    let db_configs = sqlx::query_as!(
        UserConfigDto,
        "SELECT key, value FROM user_configs AS c JOIN users AS u ON u.id = c.user_id WHERE u.username = ?",
        "admin"
    )
    .fetch_all(&ctx.db_conn)
    .await
    .unwrap();

    assert_eq!(db_configs.len(), 0);

    ctx.stop_test_server().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_config_delete_entry_non_existing() -> Result<()> {
    let mut ctx = lib::IntegrationTestContext::new("test_user_config_delete_entry_non_existing").await;
    let server_addr = ctx.start_test_server().await;
    let (client, _auth_token) = lib::create_authorized_http_client(&server_addr).await;

    let config_entry = UserConfigValueDto {
        value: "testvalue1".to_string(),
    };

    assert_post_status(
        &client,
        format!("http://{}/users/configs/testkey1", server_addr).as_str(),
        &config_entry,
        StatusCode::NO_CONTENT,
    )
    .await;

    assert_delete_status(
        &client,
        format!("http://{}/users/configs/testkey_non_existing", server_addr).as_str(),
        StatusCode::NOT_FOUND,
    )
    .await;

    let configs: Vec<UserConfigDto> = assert_get_status_deserialize(
        &client,
        format!("http://{}/users/configs", server_addr).as_str(),
        StatusCode::OK,
    )
    .await;

    assert_eq!(configs.len(), 0);

    let db_configs = sqlx::query_as!(
        UserConfigDto,
        "SELECT key, value FROM user_configs AS c JOIN users AS u ON u.id = c.user_id WHERE u.username = ?",
        "admin"
    )
    .fetch_all(&ctx.db_conn)
    .await
    .unwrap();

    assert_eq!(db_configs.len(), 1);

    ctx.stop_test_server().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_config_entry_non_existing() -> Result<()> {
    let mut ctx = lib::IntegrationTestContext::new("test_user_config_entry_non_existing").await;
    let server_addr = ctx.start_test_server().await;
    let (client, _auth_token) = lib::create_authorized_http_client(&server_addr).await;

    assert_get_status(
        &client,
        format!("http://{}/users/configs/testkey_non_existing", server_addr).as_str(),
        StatusCode::NOT_FOUND,
    )
    .await;

    ctx.stop_test_server().await?;
    Ok(())
}
