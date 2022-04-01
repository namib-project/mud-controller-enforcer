// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::module_name_repetitions)]

pub use actix_web::http::StatusCode;
use namib_shared::macaddr::ParseError;
use paperclip::actix::{api_v2_errors, web::HttpResponse};
use snafu::{Backtrace, Snafu};

/// Represents any error that can occur during runtime
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
        backtrace: Option<Backtrace>,
    },
    #[snafu(display("MudError {}", message), visibility(pub))]
    MudError { message: String, backtrace: Backtrace },
    #[snafu(display("SerdeError {}", source), context(false))]
    SerdeError {
        source: serde_json::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("SerdeYamlError {}", source), context(false))]
    SerdeYamlError { source: serde_yaml::Error },
    #[snafu(display("JsonWebTokenError {}", source), context(false))]
    JsonWebTokenError {
        source: jsonwebtoken::errors::Error,
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
    #[snafu(display("CertificateRequestError"), visibility(pub))]
    CertificateRequestError { backtrace: Backtrace },
    #[snafu(display("EnforcerNotAllowed"), visibility(pub))]
    EnforcerNotAllowed { backtrace: Backtrace },
    #[snafu(display("{:?}", message), visibility(pub))]
    InvalidUserInput {
        message: String,
        field: String,
        status: StatusCode,
    },
}

macro_rules! invalid_user_input {
    ($message: tt, $field: tt, $status: expr) => {
        |_| {
            Err(crate::error::Error::InvalidUserInput {
                message: String::from($message),
                field: String::from($field),
                status: $status,
            })
        }
    };
    ($message: tt, $field: tt) => {
        crate::error::invalid_user_input!($message, $field, crate::error::StatusCode::UNPROCESSABLE_ENTITY)
    };
}

macro_rules! response_error {
    () => {
        crate::error::response_error!(crate::error::StatusCode::BAD_REQUEST, None)
    };
    ($status: expr) => {
        crate::error::response_error!($status, None)
    };
    ($status: expr, $message: tt) => {
        |_| {
            Err(crate::error::Error::ResponseError {
                status: $status,
                message: $message,
                backtrace: None,
            })
        }
    };
}

macro_rules! map_internal {
    () => {
        crate::error::map_internal!(crate::error::StatusCode::BAD_REQUEST, None)
    };
    ($status: expr, $message: tt) => {
        |err| {
            Err(match err {
                crate::error::Error::InvalidUserInput { .. } => err,
                _ => crate::error::Error::ResponseError {
                    status: $status,
                    message: $message,
                    backtrace: None,
                },
            })
        }
    };
}

pub(crate) use invalid_user_input;
pub(crate) use map_internal;
pub(crate) use response_error;

/// A failable action
pub type Result<T> = std::result::Result<T, Error>;

pub fn none_error() -> Error {
    self::NoneError {}.build()
}

#[derive(Serialize, Deserialize)]
pub struct ErrorDto {
    pub error: String,
    pub field: Option<String>,
}

impl actix_web::ResponseError for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Error::ResponseError { status, .. } => *status,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        error!("Error during request: {:?}", self);
        let (mut rb, body) = match self {
            Error::InvalidUserInput {
                message, field, status, ..
            } => {
                let message = message.clone();
                let field = field.clone();

                (
                    HttpResponse::build(*status),
                    ErrorDto {
                        error: message,
                        field: Some(field),
                    },
                )
            },
            Error::ResponseError { status, message, .. } => {
                let message = message.clone().unwrap_or_else(|| String::from("An error occurred"));

                (
                    HttpResponse::build(*status),
                    ErrorDto {
                        error: message,
                        field: None,
                    },
                )
            },
            _ => (
                HttpResponse::InternalServerError(),
                ErrorDto {
                    error: String::from("An error occurred"),
                    field: None,
                },
            ),
        };
        rb.content_type("application/json")
            .body(serde_json::to_string(&body).unwrap())
    }
}
