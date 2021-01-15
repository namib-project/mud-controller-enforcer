#![allow(clippy::pub_enum_variant_names, clippy::module_name_repetitions)]

use isahc::http::StatusCode;
use paperclip::actix::{api_v2_errors, web::HttpResponse};
use schemars::JsonSchema;
use snafu::{Backtrace, Snafu};

#[api_v2_errors(code = 401, code = 500)]
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
    #[snafu(display("IsahcError {}", source), context(false))]
    IsahcError { source: isahc::Error, backtrace: Backtrace },
    #[snafu(display("PatternError {}", source), context(false))]
    PatternError {
        source: glob::PatternError,
        backtrace: Backtrace,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Serialize, Deserialize, JsonSchema)]
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
            }
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

/*
impl OpenApiResponder<'_> for Error {
    fn responses(gen: &mut OpenApiGenerator) -> rocket_okapi::Result<OAResponses> {
        let mut responses = OAResponses::default();
        let schema = gen.json_schema_no_ref::<ErrorDto>();
        add_schema_response(&mut responses, 401, "application/json", schema.clone())?;
        add_schema_response(&mut responses, 500, "application/json", schema)?;
        Ok(responses)
    }
}
*/
