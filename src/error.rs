#![allow(clippy::pub_enum_variant_names, clippy::module_name_repetitions)]

use actix_web::http::StatusCode;
use namib_shared::mac::ParseError;
use paperclip::actix::{api_v2_errors, web::HttpResponse};
use snafu::{Backtrace, Snafu};

#[api_v2_errors(code = 401, code = 403, code = 500)]
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("ArgonError: {}", source), context(false))]
    ArgonError {
        source: argon2::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("PasswordVerifyError"), visibility(pub))]
    PasswordVerifyError { backtrace: Backtrace },
    #[snafu(display("DatabaseError: {}", source), context(false))]
    DatabaseError {
        source: sqlx::error::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("MigrateError: {}", source), context(false))]
    MigrateError {
        source: sqlx::migrate::MigrateError,
        backtrace: Backtrace,
    },
    #[snafu(display("IoError: {}", source), context(false))]
    IoError {
        source: std::io::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("TlsError: {}", source), context(false))]
    TlsError {
        source: rustls::TLSError,
        backtrace: Backtrace,
    },
    #[snafu(display("AddrParseError: {}", source), context(false))]
    AddrParseError {
        source: std::net::AddrParseError,
        backtrace: Backtrace,
    },
    #[snafu(display("MacParseError: {}", source), context(false))]
    MacParseError { source: ParseError, backtrace: Backtrace },
    #[snafu(display("DotEnvError: {}", source), context(false))]
    DotEnvError {
        source: dotenv::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("JoinError: {}", source), context(false))]
    JoinError {
        source: tokio::task::JoinError,
        backtrace: Backtrace,
    },
    #[snafu(display("{:?}", message), visibility(pub))]
    ResponseError {
        message: Option<String>,
        status: StatusCode,
        backtrace: Backtrace,
    },
    #[snafu(display("MudError {}", message), visibility(pub))]
    MudError { message: String, backtrace: Backtrace },
    #[snafu(display("SerdeError {}", source), context(false))]
    SerdeError {
        source: serde_json::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("PatternError {}", source), context(false))]
    PatternError {
        source: glob::PatternError,
        backtrace: Backtrace,
    },
    #[snafu(display("ParseIntError {}", source), context(false))]
    ParseIntError {
        source: std::num::ParseIntError,
        backtrace: Backtrace,
    },
    #[snafu(display("ChronoParseError {}", source), context(false))]
    ChronoParseError {
        source: chrono::ParseError,
        backtrace: Backtrace,
    },
    #[snafu(display("FromStrError"), visibility(pub))]
    FromStrError { backtrace: Backtrace },
    #[snafu(display("NoneError"), visibility(pub))]
    NoneError { backtrace: Backtrace },
    #[snafu(display("AcmeError {}", source), context(false))]
    AcmeError {
        source: acme_lib::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("ReqwestError {}", source), context(false))]
    ReqwestError {
        source: reqwest::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("Neo4ThingsError {}", message), visibility(pub))]
    Neo4ThingsError { message: String, backtrace: Backtrace },
    #[snafu(display("MudFileInvalid"), visibility(pub))]
    MudFileInvalid { backtrace: Backtrace },
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn none_error() -> Error {
    self::NoneError {}.build()
}

#[derive(Serialize, Deserialize)]
pub struct ErrorDto {
    pub error: String,
}

impl actix_web::ResponseError for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Error::ResponseError { status, .. } => *status,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        error!("Error during request: {}", self);
        let (mut rb, body) = match self {
            Error::ResponseError { status, message, .. } => {
                let message = message.clone().unwrap_or_else(|| String::from("An error occurred"));

                (HttpResponse::build(*status), ErrorDto { error: message })
            },
            _ => (
                HttpResponse::InternalServerError(),
                ErrorDto {
                    error: String::from("An error occurred"),
                },
            ),
        };
        rb.content_type("application/json")
            .body(serde_json::to_string(&body).unwrap())
    }
}
