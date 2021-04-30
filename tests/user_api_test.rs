mod lib;

use lib::{
    assert_delete_status, assert_get_status, assert_get_status_deserialize, assert_post_status,
    assert_post_status_deserialize,
};
use log::info;
use namib_mud_controller::{
    auth::AuthToken,
    models::Role,
    routes::dtos::{
        LoginDto, RoleDto, SuccessDto, TokenDto, UpdatePasswordDto, UpdateUserDto, UserConfigDto, UserConfigValueDto,
    },
    services::role_service::ROLE_ID_ADMIN,
};
use reqwest::{header::HeaderMap, StatusCode};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::time::{sleep, Duration};

#[derive(Debug, Deserialize, Clone)]
pub struct UserResult {
    pub id: i64,
    pub username: String,
    pub roles: Vec<Role>,
    pub permissions: Vec<String>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_signup() {
    let ctx = lib::IntegrationTestContext::new("test_signup")
        .await
        .start_test_server()
        .await;
    let (client, _auth_token) = lib::create_authorized_http_client(&ctx.server_addr).await;

    let result: UserResult = assert_get_status_deserialize(
        &client,
        format!("http://{}/users/me", ctx.server_addr).as_str(),
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
        "SELECT COUNT(*) AS \"count!\" FROM users AS u JOIN users_roles AS r ON u.id = r.user_id WHERE u.username = $1 AND r.role_id = $2",
        "admin",
        ROLE_ID_ADMIN
    ).fetch_one(&ctx.db_conn).await.unwrap().count;
    assert_eq!(user_count, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_signup_missing_username() {
    let ctx = lib::IntegrationTestContext::new("test_first_signup_missing_username")
        .await
        .start_test_server()
        .await;
    let client = reqwest::Client::new();

    let signup_dto = json!({
        "password": "password"
    });
    assert_post_status(
        &client,
        format!("http://{}/users/signup", ctx.server_addr).as_str(),
        &signup_dto,
        StatusCode::BAD_REQUEST,
    )
    .await;

    let user_count = sqlx::query!("SELECT COUNT(*) AS \"count!\"  FROM users")
        .fetch_one(&ctx.db_conn)
        .await
        .unwrap()
        .count;
    assert_eq!(user_count, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_signup_missing_password() {
    let ctx = lib::IntegrationTestContext::new("test_first_signup_missing_password")
        .await
        .start_test_server()
        .await;
    let client = reqwest::Client::new();

    let signup_dto = json!({
        "username": "admin"
    });
    assert_post_status(
        &client,
        format!("http://{}/users/signup", ctx.server_addr).as_str(),
        &signup_dto,
        StatusCode::BAD_REQUEST,
    )
    .await;

    let user_count = sqlx::query!("SELECT COUNT(*) AS \"count!\"  FROM users")
        .fetch_one(&ctx.db_conn)
        .await
        .unwrap()
        .count;
    assert_eq!(user_count, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_signup_already_created() {
    let ctx = lib::IntegrationTestContext::new("test_signup_already_created")
        .await
        .start_test_server()
        .await;
    let (client, _auth_token) = lib::create_authorized_http_client(&ctx.server_addr).await;

    let signup_dto = json!({
        "username": "admin",
        "password": "password"
    });
    assert_post_status(
        &client,
        format!("http://{}/users/signup", ctx.server_addr).as_str(),
        &signup_dto,
        StatusCode::BAD_REQUEST,
    )
    .await;

    let user_count = sqlx::query!("SELECT COUNT(*) AS \"count!\"  FROM users WHERE username = $1", "admin")
        .fetch_one(&ctx.db_conn)
        .await
        .unwrap()
        .count;
    assert_eq!(user_count, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pw_update() {
    let ctx = lib::IntegrationTestContext::new("test_pw_update")
        .await
        .start_test_server()
        .await;
    let (client, _auth_token) = lib::create_authorized_http_client(&ctx.server_addr).await;

    let before_state = sqlx::query!(
        "SELECT password, salt FROM users AS u JOIN users_roles AS r ON u.id = r.user_id WHERE u.username = $1",
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
        format!("http://{}/users/password", ctx.server_addr).as_str(),
        &pw_update_dto,
        StatusCode::OK,
    )
    .await;

    let after_state = sqlx::query!(
        "SELECT password, salt FROM users AS u JOIN users_roles AS r ON u.id = r.user_id WHERE u.username = $1",
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
        format!("http://{}/users/login", ctx.server_addr).as_str(),
        &login_dto,
        StatusCode::OK,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pw_update_wrong_old_pw() {
    let ctx = lib::IntegrationTestContext::new("test_pw_update_wrong_old_pw")
        .await
        .start_test_server()
        .await;
    let (client, _auth_token) = lib::create_authorized_http_client(&ctx.server_addr).await;

    let before_state = sqlx::query!(
        "SELECT password, salt FROM users AS u JOIN users_roles AS r ON u.id = r.user_id WHERE u.username = $1",
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
        format!("http://{}/users/password", ctx.server_addr).as_str(),
        &pw_update_dto,
        StatusCode::UNAUTHORIZED,
    )
    .await;

    let after_state = sqlx::query!(
        "SELECT password, salt FROM users AS u JOIN users_roles AS r ON u.id = r.user_id WHERE u.username = $1",
        "admin"
    )
    .fetch_one(&ctx.db_conn)
    .await
    .unwrap();

    assert_eq!(before_state.password, after_state.password);
    assert_eq!(before_state.salt, after_state.salt);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pw_update_not_logged_in() {
    let ctx = lib::IntegrationTestContext::new("test_pw_update_not_logged_in")
        .await
        .start_test_server()
        .await;
    lib::create_authorized_http_client(&ctx.server_addr).await;
    let client = reqwest::Client::new();

    let before_state = sqlx::query!(
        "SELECT password, salt FROM users AS u JOIN users_roles AS r ON u.id = r.user_id WHERE u.username = $1",
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
        format!("http://{}/users/password", ctx.server_addr).as_str(),
        &pw_update_dto,
        StatusCode::UNAUTHORIZED,
    )
    .await;

    let after_state = sqlx::query!(
        "SELECT password, salt FROM users AS u JOIN users_roles AS r ON u.id = r.user_id WHERE u.username = $1",
        "admin"
    )
    .fetch_one(&ctx.db_conn)
    .await
    .unwrap();

    assert_eq!(before_state.password, after_state.password);
    assert_eq!(before_state.salt, after_state.salt);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_username_update() {
    let ctx = lib::IntegrationTestContext::new("test_username_update")
        .await
        .start_test_server()
        .await;
    let (client, _auth_token) = lib::create_authorized_http_client(&ctx.server_addr).await;

    let user_update_dto = UpdateUserDto {
        username: Some(String::from("new_admin")),
    };
    let _result: SuccessDto = assert_post_status_deserialize(
        &client,
        format!("http://{}/users/me", ctx.server_addr).as_str(),
        &user_update_dto,
        StatusCode::OK,
    )
    .await;

    let old_name_count = sqlx::query!(
        "SELECT COUNT(*) AS \"count!\"  FROM users AS u JOIN users_roles AS r ON u.id = r.user_id WHERE u.username = $1",
        "admin"
    )
    .fetch_one(&ctx.db_conn)
    .await
    .unwrap()
    .count;

    let new_name_count = sqlx::query!(
        "SELECT COUNT(*) AS \"count!\"  FROM users AS u JOIN users_roles AS r ON u.id = r.user_id WHERE u.username = $1",
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
        format!("http://{}/users/login", ctx.server_addr).as_str(),
        &login_dto,
        StatusCode::OK,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_username_update_not_logged_in() {
    let ctx = lib::IntegrationTestContext::new("test_username_update_not_logged_in")
        .await
        .start_test_server()
        .await;
    let (_client, _auth_token) = lib::create_authorized_http_client(&ctx.server_addr).await;
    let client = reqwest::Client::new();

    let user_update_dto = UpdateUserDto {
        username: Some(String::from("new_admin")),
    };
    assert_post_status(
        &client,
        format!("http://{}/users/me", ctx.server_addr).as_str(),
        &user_update_dto,
        StatusCode::UNAUTHORIZED,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_username_update_none() {
    let ctx = lib::IntegrationTestContext::new("test_username_update_none")
        .await
        .start_test_server()
        .await;
    let (client, _auth_token) = lib::create_authorized_http_client(&ctx.server_addr).await;

    let user_update_dto = UpdateUserDto { username: None };
    let _result: SuccessDto = assert_post_status_deserialize(
        &client,
        format!("http://{}/users/me", ctx.server_addr).as_str(),
        &user_update_dto,
        StatusCode::OK,
    )
    .await;

    let old_name_count = sqlx::query!(
        "SELECT COUNT(*) AS \"count!\"  FROM users AS u JOIN users_roles AS r ON u.id = r.user_id WHERE u.username = $1",
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
        format!("http://{}/users/login", ctx.server_addr).as_str(),
        &login_dto,
        StatusCode::OK,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_token_refresh() {
    let ctx = lib::IntegrationTestContext::new("test_token_refresh")
        .await
        .start_test_server()
        .await;
    let (client, auth_token) = lib::create_authorized_http_client(&ctx.server_addr).await;

    sleep(Duration::from_secs(2)).await;
    let new_token: TokenDto = assert_get_status_deserialize(
        &client,
        format!("http://{}/users/refresh_token", ctx.server_addr).as_str(),
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
        format!("http://{}/users/me", ctx.server_addr).as_str(),
        StatusCode::OK,
    )
    .await;
    info!("{:?}", result);
    assert_eq!(result.username, "admin");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_config_empty() {
    let ctx = lib::IntegrationTestContext::new("test_user_config_empty")
        .await
        .start_test_server()
        .await;
    let (client, _auth_token) = lib::create_authorized_http_client(&ctx.server_addr).await;

    let configs: Vec<UserConfigDto> = assert_get_status_deserialize(
        &client,
        format!("http://{}/users/configs", ctx.server_addr).as_str(),
        StatusCode::OK,
    )
    .await;

    assert!(configs.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_config_not_logged_in() {
    let ctx = lib::IntegrationTestContext::new("test_user_config_not_logged_in")
        .await
        .start_test_server()
        .await;
    let (_client, _auth_token) = lib::create_authorized_http_client(&ctx.server_addr).await;
    let client = reqwest::Client::new();

    assert_get_status(
        &client,
        format!("http://{}/users/configs", ctx.server_addr).as_str(),
        StatusCode::UNAUTHORIZED,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_config_add_single_entry() {
    let ctx = lib::IntegrationTestContext::new("test_user_config_add_single_entry")
        .await
        .start_test_server()
        .await;
    let (client, _auth_token) = lib::create_authorized_http_client(&ctx.server_addr).await;

    let config_entry = UserConfigValueDto {
        value: "testvalue1".to_string(),
    };

    assert_post_status(
        &client,
        format!("http://{}/users/configs/testkey1", ctx.server_addr).as_str(),
        &config_entry,
        StatusCode::NO_CONTENT,
    )
    .await;

    let configs: Vec<UserConfigDto> = assert_get_status_deserialize(
        &client,
        format!("http://{}/users/configs", ctx.server_addr).as_str(),
        StatusCode::OK,
    )
    .await;

    assert_eq!(configs.len(), 1);
    assert_eq!(configs.get(0).unwrap().key, "testkey1");
    assert_eq!(configs.get(0).unwrap().value, "testvalue1");

    let config: UserConfigDto = assert_get_status_deserialize(
        &client,
        format!("http://{}/users/configs/testkey1", ctx.server_addr).as_str(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(config.key, "testkey1");
    assert_eq!(config.value, "testvalue1");

    let db_configs = sqlx::query_as!(
        UserConfigDto,
        "SELECT key, value FROM user_configs AS c JOIN users AS u ON u.id = c.user_id WHERE u.username = $1",
        "admin"
    )
    .fetch_all(&ctx.db_conn)
    .await
    .unwrap();

    assert_eq!(db_configs.len(), 1);
    assert_eq!(db_configs.get(0).unwrap().key, "testkey1");
    assert_eq!(db_configs.get(0).unwrap().value, "testvalue1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_config_add_multiple_entries() {
    let ctx = lib::IntegrationTestContext::new("test_user_config_add_multiple_entries")
        .await
        .start_test_server()
        .await;
    let (client, _auth_token) = lib::create_authorized_http_client(&ctx.server_addr).await;

    let config_entry = UserConfigValueDto {
        value: "testvalue1".to_string(),
    };
    let config_entry2 = UserConfigValueDto {
        value: "testvalue2".to_string(),
    };

    assert_post_status(
        &client,
        format!("http://{}/users/configs/testkey1", ctx.server_addr).as_str(),
        &config_entry,
        StatusCode::NO_CONTENT,
    )
    .await;

    assert_post_status(
        &client,
        format!("http://{}/users/configs/testkey2", ctx.server_addr).as_str(),
        &config_entry2,
        StatusCode::NO_CONTENT,
    )
    .await;

    let configs: Vec<UserConfigDto> = assert_get_status_deserialize(
        &client,
        format!("http://{}/users/configs", ctx.server_addr).as_str(),
        StatusCode::OK,
    )
    .await;

    assert_eq!(configs.len(), 2);

    let config: UserConfigDto = assert_get_status_deserialize(
        &client,
        format!("http://{}/users/configs/testkey1", ctx.server_addr).as_str(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(config.key, "testkey1");
    assert_eq!(config.value, "testvalue1");

    let db_configs_count = sqlx::query!(
        "SELECT COUNT(*) AS \"count!\"  FROM user_configs AS c JOIN users AS u ON u.id = c.user_id WHERE u.username = $1",
        "admin"
    )
    .fetch_one(&ctx.db_conn)
    .await
    .unwrap()
    .count;
    assert_eq!(db_configs_count, 2);

    let db_config_1 = sqlx::query_as!(
        UserConfigDto,
        "SELECT key, value FROM user_configs AS c JOIN users AS u ON u.id = c.user_id WHERE u.username = $1 AND c.key = $2",
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
        "SELECT key, value FROM user_configs AS c JOIN users AS u ON u.id = c.user_id WHERE u.username = $1 AND c.key = $2",
        "admin",
        "testkey2"
    )
        .fetch_one(&ctx.db_conn)
        .await
        .unwrap();

    assert_eq!(db_config_2.key, "testkey2");
    assert_eq!(db_config_2.value, "testvalue2");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_config_update_entry() {
    let ctx = lib::IntegrationTestContext::new("test_user_config_update_single_entry")
        .await
        .start_test_server()
        .await;
    let (client, _auth_token) = lib::create_authorized_http_client(&ctx.server_addr).await;

    let config_entry = UserConfigValueDto {
        value: "testvalue1".to_string(),
    };

    assert_post_status(
        &client,
        format!("http://{}/users/configs/testkey1", ctx.server_addr).as_str(),
        &config_entry,
        StatusCode::NO_CONTENT,
    )
    .await;

    let config_entry = UserConfigValueDto {
        value: "testvalue1_new".to_string(),
    };

    assert_post_status(
        &client,
        format!("http://{}/users/configs/testkey1", ctx.server_addr).as_str(),
        &config_entry,
        StatusCode::NO_CONTENT,
    )
    .await;

    let configs: Vec<UserConfigDto> = assert_get_status_deserialize(
        &client,
        format!("http://{}/users/configs", ctx.server_addr).as_str(),
        StatusCode::OK,
    )
    .await;

    assert_eq!(configs.len(), 1);
    assert_eq!(configs.get(0).unwrap().key, "testkey1");
    assert_eq!(configs.get(0).unwrap().value, "testvalue1_new");

    let config: UserConfigDto = assert_get_status_deserialize(
        &client,
        format!("http://{}/users/configs/testkey1", ctx.server_addr).as_str(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(config.key, "testkey1");
    assert_eq!(config.value, "testvalue1_new");

    let db_configs = sqlx::query_as!(
        UserConfigDto,
        "SELECT key, value FROM user_configs AS c JOIN users AS u ON u.id = c.user_id WHERE u.username = $1",
        "admin"
    )
    .fetch_all(&ctx.db_conn)
    .await
    .unwrap();

    assert_eq!(db_configs.len(), 1);
    assert_eq!(db_configs.get(0).unwrap().key, "testkey1");
    assert_eq!(db_configs.get(0).unwrap().value, "testvalue1_new");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_config_delete_entry() {
    let ctx = lib::IntegrationTestContext::new("test_user_config_delete_entry")
        .await
        .start_test_server()
        .await;
    let (client, _auth_token) = lib::create_authorized_http_client(&ctx.server_addr).await;

    let config_entry = UserConfigValueDto {
        value: "testvalue1".to_string(),
    };

    assert_post_status(
        &client,
        format!("http://{}/users/configs/testkey1", ctx.server_addr).as_str(),
        &config_entry,
        StatusCode::NO_CONTENT,
    )
    .await;

    assert_delete_status(
        &client,
        format!("http://{}/users/configs/testkey1", ctx.server_addr).as_str(),
        StatusCode::NO_CONTENT,
    )
    .await;

    let configs: Vec<UserConfigDto> = assert_get_status_deserialize(
        &client,
        format!("http://{}/users/configs", ctx.server_addr).as_str(),
        StatusCode::OK,
    )
    .await;

    assert_eq!(configs.len(), 0);

    let db_configs = sqlx::query_as!(
        UserConfigDto,
        "SELECT key, value FROM user_configs AS c JOIN users AS u ON u.id = c.user_id WHERE u.username = $1",
        "admin"
    )
    .fetch_all(&ctx.db_conn)
    .await
    .unwrap();

    assert_eq!(db_configs.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_config_delete_entry_non_existing() {
    let ctx = lib::IntegrationTestContext::new("test_user_config_delete_entry_non_existing")
        .await
        .start_test_server()
        .await;
    let (client, _auth_token) = lib::create_authorized_http_client(&ctx.server_addr).await;

    let config_entry = UserConfigValueDto {
        value: "testvalue1".to_string(),
    };

    assert_post_status(
        &client,
        format!("http://{}/users/configs/testkey1", ctx.server_addr).as_str(),
        &config_entry,
        StatusCode::NO_CONTENT,
    )
    .await;

    assert_delete_status(
        &client,
        format!("http://{}/users/configs/testkey_non_existing", ctx.server_addr).as_str(),
        StatusCode::NO_CONTENT,
    )
    .await;

    let configs: Vec<UserConfigDto> = assert_get_status_deserialize(
        &client,
        format!("http://{}/users/configs", ctx.server_addr).as_str(),
        StatusCode::OK,
    )
    .await;

    assert_eq!(configs.len(), 1);

    let db_configs = sqlx::query_as!(
        UserConfigDto,
        "SELECT key, value FROM user_configs AS c JOIN users AS u ON u.id = c.user_id WHERE u.username = $1",
        "admin"
    )
    .fetch_all(&ctx.db_conn)
    .await
    .unwrap();

    assert_eq!(db_configs.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_config_entry_non_existing() {
    let ctx = lib::IntegrationTestContext::new("test_user_config_entry_non_existing")
        .await
        .start_test_server()
        .await;
    let (client, _auth_token) = lib::create_authorized_http_client(&ctx.server_addr).await;

    assert_get_status(
        &client,
        format!("http://{}/users/configs/testkey_non_existing", ctx.server_addr).as_str(),
        StatusCode::NOT_FOUND,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_usermanagement_roles() {
    let ctx = lib::IntegrationTestContext::new("test_usermanagement_roles")
        .await
        .start_test_server()
        .await;
    let (client, _auth_token) = lib::create_authorized_http_client(&ctx.server_addr).await;

    let roles: Vec<RoleDto> =
        assert_get_status_deserialize(&client, &format!("http://{}/roles/", ctx.server_addr), StatusCode::OK).await;

    let new_user: Value = assert_post_status_deserialize(
        &client,
        &format!("http://{}/management/users/", ctx.server_addr),
        &json!({"username": "testman", "password": "iamverysecure", "roles_ids": []}),
        StatusCode::OK,
    )
    .await;

    assert_post_status(
        &client,
        format!("http://{}/roles/assign", ctx.server_addr).as_str(),
        &json!({"role_id": roles.iter().find(|r| r.name == "reader").unwrap().id, "user_id": new_user["id"]}),
        StatusCode::NO_CONTENT,
    )
    .await;

    assert_post_status(
        &reqwest::Client::new(),
        format!("http://{}/users/login", ctx.server_addr).as_str(),
        &json!({"username": "testman", "password": "iamverysecure"}),
        StatusCode::OK,
    )
    .await;

    assert_post_status(
        &client,
        format!("http://{}/roles/assign", ctx.server_addr).as_str(),
        &json!({"role_id": roles.iter().find(|r| r.name == "admin").unwrap().id, "user_id": new_user["id"]}),
        StatusCode::NO_CONTENT,
    )
    .await;

    let usrs: Value = assert_get_status_deserialize(
        &client,
        &format!("http://{}/management/users/", ctx.server_addr),
        StatusCode::OK,
    )
    .await;

    assert_eq!(
        usrs.as_array()
            .unwrap()
            .iter()
            .find(|u| u["username"] == "testman")
            .unwrap()["roles"],
        json!([{"name": "reader", "id": 1}, {"name": "admin", "id": 0}])
    );

    assert_post_status(
        &client,
        format!("http://{}/roles/unassign", ctx.server_addr).as_str(),
        &json!({"role_id": roles.iter().find(|r| r.name == "reader").unwrap().id, "user_id": new_user["id"]}),
        StatusCode::NO_CONTENT,
    )
    .await;

    let usrs: Value = assert_get_status_deserialize(
        &client,
        &format!("http://{}/management/users/", ctx.server_addr),
        StatusCode::OK,
    )
    .await;

    assert_eq!(
        usrs.as_array()
            .unwrap()
            .iter()
            .find(|u| u["username"] == "testman")
            .unwrap()["roles"],
        json!([{"name": "admin", "id": 0}])
    );

    let login: TokenDto = assert_post_status_deserialize(
        &reqwest::Client::new(),
        format!("http://{}/users/login", ctx.server_addr).as_str(),
        &json!({"username": "testman", "password": "iamverysecure"}),
        StatusCode::OK,
    )
    .await;

    let auth = AuthToken::decode_token(&login.token).unwrap();
    assert_eq!(auth.permissions, vec!["**"]);

    let mut headers = HeaderMap::new();
    headers.insert("authorization", format!("Bearer {}", login.token).parse().unwrap());
    assert_delete_status(
        &reqwest::ClientBuilder::new().default_headers(headers).build().unwrap(),
        format!("http://{}/management/users/{}", ctx.server_addr, new_user["id"]).as_str(),
        StatusCode::NO_CONTENT,
    )
    .await;
}
