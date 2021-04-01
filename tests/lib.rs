#[cfg(feature = "postgres")]
use std::env;

use dotenv::dotenv;
use log::{debug, error, info};
use sqlx::migrate;

use futures::executor::block_on;
use namib_mud_controller::{
    controller::app,
    db::DbConnection,
    error::Result,
    routes::dtos::{LoginDto, SignupDto, SuccessDto, TokenDto},
};
use reqwest::{header::HeaderMap, Client, StatusCode};
use serde::{de::DeserializeOwned, Serialize};
use snafu::{Backtrace, GenerateBacktrace};
use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    str::FromStr,
    sync::Arc,
};
use tokio::{
    sync::{
        oneshot::{Receiver, Sender},
        Mutex,
    },
    task::JoinHandle,
};

pub const API_TEST_SOCKADDR: &str = "127.0.0.1:0";

pub struct IntegrationTestContext {
    pub db_url: String,
    pub db_name: &'static str,
    pub db_conn: DbConnection,
    server_task: Option<JoinHandle<Result<()>>>,
    end_signal_send: Option<Sender<()>>,
}

impl IntegrationTestContext {
    /// Creates a new DB context, so you can access the database.
    /// Added a db_name option, so tests can run parallel and independent
    /// When using SQLite, TESTING_DATABASE_URL is a path where the sqlite files are created
    pub async fn new(db_name: &'static str) -> Self {
        dotenv().ok();
        env_logger::try_init().ok();

        #[cfg(feature = "sqlite")]
        let db_url = format!("sqlite:{}?mode=memory", db_name);

        #[cfg(feature = "postgres")]
        let db_url = format!(
            "{}/{}",
            env::var("DATABASE_URL").expect("Failed to load DB URL from .env"),
            db_name
        );

        info!("Using DB {:?}", db_url);

        let db_conn = DbConnection::connect(&db_url)
            .await
            .expect("Couldn't establish connection pool for database");

        #[cfg(feature = "sqlite")]
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
            server_task: None,
            end_signal_send: None,
        }
    }

    pub async fn start_test_server(&mut self) -> SocketAddr {
        let (end_signal_send, end_signal_rec) = tokio::sync::oneshot::channel();
        self.end_signal_send = Some(end_signal_send);
        let conn = self.db_conn.clone();
        let server_addr = actix_web::test::unused_addr();
        let (startup_complete_send, startup_complete_recv) = tokio::sync::oneshot::channel();
        self.server_task = Some(tokio::task::spawn_blocking(move || {
            app(
                conn,
                end_signal_rec,
                server_addr.clone(),
                None,
                Some(2),
                Some(startup_complete_send),
            )
        }));
        startup_complete_recv.await;
        server_addr
    }

    pub async fn stop_test_server(&mut self) -> Result<()> {
        if let Some(ess) = self.end_signal_send.take() {
            ess.send(()).unwrap();
            if let Some(st) = self.server_task.take() {
                match st.await {
                    Ok(Ok(())) => {},
                    Ok(Err(e)) => {
                        error!("Error in HTTP Server: {:?}", e);
                        return Err(e);
                    },
                    Err(e) => {
                        error!("Error while stopping HTTP Server: {:?}", e);
                        return Err(namib_mud_controller::error::Error::NoneError {
                            backtrace: Backtrace::generate(),
                        });
                    },
                }
            } else {
                error!("Error while acquiring server task.");
                return Err(namib_mud_controller::error::Error::NoneError {
                    backtrace: Backtrace::generate(),
                });
            }
        } else {
            error!("Error while acquiring server end signal sender.");
            return Err(namib_mud_controller::error::Error::NoneError {
                backtrace: Backtrace::generate(),
            });
        }
        Ok(())
    }
}

#[cfg(feature = "postgres")]
impl Drop for IntegrationTestContext {
    /// Removes/cleans the DB context
    fn drop(&mut self) {
        if (self.server_task.is_some()) {
            block_on(self.stop_test_server()).unwrap();
            info!("Stopped HTTP server");
        }
        sqlx::query("DROP DATABASE " + self.db_name);
        info!("Cleaned up database context");
    }
}

#[cfg(not(feature = "postgres"))]
impl Drop for IntegrationTestContext {
    /// Removes/cleans the DB context
    fn drop(&mut self) {
        if (self.server_task.is_some()) {
            block_on(self.stop_test_server()).unwrap();
            info!("Stopped HTTP server");
        }
    }
}

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

pub async fn assert_post_successful<B: Serialize+?Sized, O: DeserializeOwned>(
    client: &Client,
    url: &str,
    body: &B,
) -> O {
    let req_result = client.post(url).json(body).send().await.unwrap();
    assert_eq!(req_result.status(), StatusCode::OK);
    req_result.json().await.unwrap()
}

pub async fn assert_post_failure<B: Serialize+?Sized>(client: &Client, url: &str, body: &B, status_code: StatusCode) {
    assert_eq!(client.post(url).json(body).send().await.unwrap().status(), status_code)
}

pub async fn assert_get_successful<O: DeserializeOwned>(client: &Client, url: &str) -> O {
    let req_result = client.get(url).send().await.unwrap();
    assert_eq!(req_result.status(), StatusCode::OK);
    req_result.json().await.unwrap()
}

pub async fn assert_get_failure(client: &Client, url: &str, status_code: StatusCode) {
    assert_eq!(client.get(url).send().await.unwrap().status(), status_code)
}
