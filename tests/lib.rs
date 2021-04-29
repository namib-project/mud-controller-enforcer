use std::{net::SocketAddr, ops::Deref};

use dispose::{Disposable, Dispose};
use dotenv::dotenv;
use futures::executor::block_on;
use log::{debug, info};
use namib_mud_controller::{
    app::{ControllerAppBuilder, ControllerAppWrapper},
    db::DbConnection,
    routes::dtos::{LoginDto, SignupDto, SuccessDto, TokenDto},
};
use reqwest::{header::HeaderMap, Client, StatusCode};
use serde::{de::DeserializeOwned, Serialize};
use sqlx::migrate;

pub struct IntegrationTestContext {
    pub db_url: String,
    pub db_name: &'static str,
    pub db_conn: DbConnection,
}

pub struct IntegrationTestContextWithApp {
    ctx: IntegrationTestContext,
    server_instance: ControllerAppWrapper,
    pub server_addr: SocketAddr,
}

impl Deref for IntegrationTestContextWithApp {
    type Target = IntegrationTestContext;

    fn deref(&self) -> &Self::Target {
        &self.ctx
    }
}

impl IntegrationTestContext {
    /// Creates a new DB context, so you can access the database.
    /// Added a db_name option, so tests can run parallel and independent
    /// When using SQLite, TESTING_DATABASE_URL is a path where the sqlite files are created
    pub async fn new(db_name: &'static str) -> Self {
        dotenv().ok();
        env_logger::try_init().ok();

        #[cfg(not(feature = "postgres"))]
        let db_url = format!("sqlite:file:{}?mode=memory", db_name);

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
        {
            migrate!("migrations/sqlite")
                .run(&db_conn)
                .await
                .expect("Database migrations failed");
        }

        #[cfg(feature = "postgres")]
        {
            migrate!("migrations/postgres")
                .run(&db_conn)
                .await
                .expect("Database migrations failed");
        }

        Self {
            db_url,
            db_name,
            db_conn,
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
    pub async fn start_test_server(self) -> Disposable<IntegrationTestContextWithApp> {
        let server_addr = actix_web::test::unused_addr();
        let ctx = IntegrationTestContextWithApp {
            server_instance: ControllerAppBuilder::default()
                .conn(self.db_conn.clone())
                .http_addrs(vec![server_addr])
                .worker_count(2)
                .start()
                .await
                .expect("Error while starting server."),
            ctx: self,
            server_addr,
        };
        Disposable::new(ctx)
    }
}

/// we need to implement dispose, since drop() only takes a reference to self and stop_server requires moving
impl Dispose for IntegrationTestContextWithApp {
    fn dispose(self) {
        block_on(self.server_instance.stop_server()).unwrap();
        info!("Stopped HTTP server");
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
pub async fn assert_post_status_deserialize<B: Serialize, O: DeserializeOwned>(
    client: &Client,
    url: &str,
    body: &B,
    status_code: StatusCode,
) -> O {
    let req_result = client.post(url).json(body).send().await.unwrap();
    assert_eq!(
        req_result.status(),
        status_code,
        "Status code mismatch. Response: {:?}",
        req_result.text().await
    );
    req_result.json().await.unwrap()
}

/// Perform a POST request to the API using the given client, url, body and expected status code.
/// Will fail if the status code does not match or the request itself fails.
// Not actually dead code, wrongly detected as such because it is in lib.rs.
#[allow(dead_code)]
pub async fn assert_post_status<B: Serialize>(client: &Client, url: &str, body: &B, status_code: StatusCode) {
    assert_eq!(client.post(url).json(body).send().await.unwrap().status(), status_code)
}

/// Perform a PUT request to the API using the given client, url, body and expected status code.
/// Will fail if the status code does not match or the request itself fails.
// Not actually dead code, wrongly detected as such because it is in lib.rs.
#[allow(dead_code)]
pub async fn assert_put_status<B: Serialize>(client: &Client, url: &str, body: &B, status_code: StatusCode) {
    assert_eq!(client.put(url).json(body).send().await.unwrap().status(), status_code)
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
