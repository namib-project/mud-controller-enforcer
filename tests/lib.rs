#[cfg(feature = "postgres")]
use std::env;
use std::net::SocketAddr;

use dotenv::dotenv;
use futures::executor::block_on;
#[cfg(feature = "postgres")]
use log::error;
use log::{debug, info};
use namib_mud_controller::{
    controller::ControllerAppWrapper,
    db::DbConnection,
    error::Result,
    routes::dtos::{LoginDto, SignupDto, SuccessDto, TokenDto},
};
use reqwest::{header::HeaderMap, Client, StatusCode};
use serde::{de::DeserializeOwned, Serialize};
use sqlx::migrate;

pub struct IntegrationTestContext {
    pub db_url: String,
    pub db_name: &'static str,
    pub db_conn: DbConnection,
    server_instance: Option<ControllerAppWrapper>,
}

impl IntegrationTestContext {
    /// Creates a new DB context, so you can access the database.
    /// Added a db_name option, so tests can run parallel and independent
    /// When using SQLite, TESTING_DATABASE_URL is a path where the sqlite files are created
    pub async fn new(db_name: &'static str) -> Self {
        dotenv().ok();
        env_logger::try_init().ok();

        #[cfg(not(feature = "postgres"))]
        let db_url = "sqlite::memory:".to_string();
        // No longer supported as of sqlx 0.5.X
        //let db_url = format!("sqlite:{}?mode=memory", db_name);

        #[cfg(feature = "postgres")]
        let db_url = {
            let mut url =
                url::Url::parse(&std::env::var("DATABASE_URL").expect("Failed to load DB URL from .env")).unwrap();
            let db_name = format!("__{}", db_name);
            let conn = DbConnection::connect(url.as_str()).await.unwrap();
            sqlx::query(&format!("DROP DATABASE IF EXISTS {}", db_name))
                .execute(&conn)
                .await
                .unwrap();
            sqlx::query(&format!("CREATE DATABASE {}", db_name))
                .execute(&conn)
                .await
                .unwrap();
            url.set_path(&db_name);
            url.to_string()
        };

        info!("Using DB {:?}", db_url);

        let db_conn = DbConnection::connect(&db_url)
            .await
            .expect("Couldn't establish connection pool for database");

        #[cfg(not(feature = "postgres"))]
        migrate!("migrations/sqlite")
            .run(&db_conn)
            .await
            .expect("Database migrations failed");

        #[cfg(feature = "postgres")]
        migrate!("migrations/postgres")
            .run(&db_conn)
            .await
            .expect("Database migrations failed");

        Self {
            db_url,
            db_name,
            db_conn,
            server_instance: None,
        }
    }

    /// Start a test server instance of the controller using the database of this context and return
    /// the socket address under which it is available.
    ///
    /// The socket address is chosen at random using actix_web::test::unused_addr().
    ///
    /// Note that you should make sure to stop the server using stop_test_server() to ensure that potential
    /// errors in the server instance are caught.
    // Not actually dead code, wrongly detected as such because it is in lib.rs.
    #[allow(dead_code)]
    pub async fn start_test_server(&mut self) -> SocketAddr {
        if self.server_instance.is_some() {
            panic!(
                "start_test_server() called even though a server instance is already running for the given context."
            );
        }
        let conn = self.db_conn.clone();
        let server_addr = actix_web::test::unused_addr();
        self.server_instance = Some(
            ControllerAppWrapper::start_new_server(conn, vec![server_addr.clone()], Vec::new(), Some(2))
                .await
                .expect("Error while starting server."),
        );
        server_addr
    }

    /// Stops the test server instance created from this context.
    pub async fn stop_test_server(&mut self) -> Result<()> {
        if let Some(server_instance) = self.server_instance.take() {
            server_instance.stop_server().await.unwrap_or_else(|e| Err(e.into()))
        } else {
            panic!("Attempted to stop server that was not started.");
        }
    }
}

#[cfg(feature = "postgres")]
impl Drop for IntegrationTestContext {
    /// Removes/cleans the DB context
    fn drop(&mut self) {
        if self.server_instance.is_some() {
            block_on(self.stop_test_server()).unwrap();
            info!("Stopped HTTP server");
        }
        if let Err(e) =
            block_on(sqlx::query(("DROP DATABASE __".to_owned() + self.db_name).as_str()).execute(&self.db_conn))
        {
            error!("Error while dropping database {}: {:?}", self.db_name, e)
        }
        info!("Cleaned up database context");
    }
}

#[cfg(not(feature = "postgres"))]
impl Drop for IntegrationTestContext {
    /// Removes/cleans the DB context
    fn drop(&mut self) {
        if self.server_instance.is_some() {
            block_on(self.stop_test_server()).unwrap();
            info!("Stopped HTTP server");
        }
    }
}

/// Create an HTTP client suitable for performing authorized requests to the API.
/// To accomplish this, this call will also create the admin user by calling the /users/signup endpoint.
/// This function should only be called once per test (server) instance.
// Not actually dead code, wrongly detected as such because it is in lib.rs.
#[allow(dead_code)]
pub async fn create_authorized_http_client(server_addr: &SocketAddr) -> (Client, TokenDto) {
    let signup_dto = SignupDto {
        username: String::from("admin"),
        password: String::from("password"),
    };
    let login_dto = LoginDto {
        username: String::from("admin"),
        password: String::from("password"),
    };
    let client = reqwest::Client::new();
    let signup_response: SuccessDto = client
        .post(format!("http://{}/users/signup", server_addr))
        .json(&signup_dto)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    debug!("Signup Status: {:?}", signup_response.status);
    let auth_response = client
        .post(format!("http://{}/users/login", server_addr))
        .json(&login_dto)
        .send()
        .await
        .unwrap();
    let auth_token: TokenDto = auth_response.json().await.unwrap();
    debug!("Auth Token: {:?}", &auth_token.token);
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        (String::from("Bearer ") + auth_token.token.as_str()).parse().unwrap(),
    );
    (
        reqwest::ClientBuilder::new().default_headers(headers).build().unwrap(),
        auth_token,
    )
}

/// Perform a POST request to the API using the given client, url, body and expected status code
/// and deserialize the result using reqwest::async_impl::Response::json().
/// Will fail if the status code does not match or either the request itself or deserialization fails.
// Not actually dead code, wrongly detected as such because it is in lib.rs.
#[allow(dead_code)]
pub async fn assert_post_status_deserialize<B: Serialize+?Sized, O: DeserializeOwned>(
    client: &Client,
    url: &str,
    body: &B,
    status_code: StatusCode,
) -> O {
    let req_result = client.post(url).json(body).send().await.unwrap();
    assert_eq!(req_result.status(), status_code);
    req_result.json().await.unwrap()
}

/// Perform a POST request to the API using the given client, url, body and expected status code.
/// Will fail if the status code does not match or the request itself fails.
// Not actually dead code, wrongly detected as such because it is in lib.rs.
#[allow(dead_code)]
pub async fn assert_post_status<B: Serialize+?Sized>(client: &Client, url: &str, body: &B, status_code: StatusCode) {
    assert_eq!(client.post(url).json(body).send().await.unwrap().status(), status_code)
}

/// Perform a DELETE request to the API using the given client, url and expected status code.
/// Will fail if the status code does not match or the request itself fails.
// Not actually dead code, wrongly detected as such because it is in lib.rs.
#[allow(dead_code)]
pub async fn assert_delete_status(client: &Client, url: &str, status_code: StatusCode) {
    assert_eq!(client.delete(url).send().await.unwrap().status(), status_code)
}

/// Perform a GET request to the API using the given client, url and expected status code and
/// deserialize the result using reqwest::async_impl::Response::json().
/// Will fail if the status code does not match or either the request itself or deserialization fails.
// Not actually dead code, wrongly detected as such because it is in lib.rs.
#[allow(dead_code)]
pub async fn assert_get_status_deserialize<O: DeserializeOwned>(
    client: &Client,
    url: &str,
    status_code: StatusCode,
) -> O {
    let req_result = client.get(url).send().await.unwrap();
    assert_eq!(req_result.status(), status_code);
    req_result.json().await.unwrap()
}

/// Perform a GET request to the API using the given client, url and expected status code.
/// Will fail if the status code does not match or the request itself fails.
// Not actually dead code, wrongly detected as such because it is in lib.rs.
#[allow(dead_code)]
pub async fn assert_get_status(client: &Client, url: &str, status_code: StatusCode) {
    assert_eq!(client.get(url).send().await.unwrap().status(), status_code)
}
