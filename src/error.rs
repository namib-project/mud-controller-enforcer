#![allow(clippy::pub_enum_variant_names, clippy::module_name_repetitions)]

use okapi::openapi3::Responses as OAResponses;
use rocket::{http::Status, response::Responder, Request, Response};
use rocket_contrib::json::Json;
use rocket_okapi::{gen::OpenApiGenerator, response::OpenApiResponder, util::add_schema_response};
use schemars::JsonSchema;
use snafu::{Backtrace, Snafu};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("ArgonError: {}", source), context(false))]
    ArgonError { source: argon2::Error, backtrace: Backtrace },
    #[snafu(display("PasswordVerifyError"), visibility(pub))]
    PasswordVerifyError { backtrace: Backtrace },
    #[snafu(display("DatabaseError: {}", source), context(false))]
    DatabaseError { source: diesel::result::Error, backtrace: Backtrace },
    #[snafu(display("IoError: {}", source), context(false))]
    IoError { source: std::io::Error, backtrace: Backtrace },
    #[snafu(display("TlsError: {}", source), context(false))]
    TlsError { source: rustls::TLSError, backtrace: Backtrace },
    #[snafu(display("AddrParseError: {}", source), context(false))]
    AddrParseError { source: std::net::AddrParseError, backtrace: Backtrace },
    #[snafu(display("DotEnvError: {}", source), context(false))]
    DotEnvError { source: dotenv::Error, backtrace: Backtrace },
    #[snafu(display("JoinError: {}", source), context(false))]
    JoinError { source: tokio::task::JoinError, backtrace: Backtrace },
    #[snafu(display("LaunchError: {}", source), context(false))]
    LaunchError { source: rocket::error::LaunchError, backtrace: Backtrace },
    #[snafu(display("{:?}", message), visibility(pub))]
    ResponseError { message: Option<String>, status: Status, backtrace: Backtrace },
    #[snafu(display("MudError {}", message), visibility(pub))]
    MudError { message: String, backtrace: Backtrace },
    #[snafu(display("SerdeError {}", source), visibility(pub), context(false))]
    SerdeError { source: serde_json::Error, backtrace: Backtrace },
    #[snafu(display("IsahcError {}", source), visibility(pub), context(false))]
    IsahcError { source: isahc::Error, backtrace: Backtrace },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ErrorDto {
    pub error: String,
}

impl<'r> Responder<'r> for Error {
    fn respond_to(self, request: &Request) -> rocket::response::Result<'r> {
        error!("Error during request: {}", self);
        match self {
            Error::ResponseError { status, message, .. } => {
                let message = message.unwrap_or_else(|| String::from("An error occurred"));

                Response::build_from(Json(ErrorDto { error: message }).respond_to(&request)?).status(status).ok()
            },
            _ => Response::build_from(
                Json(ErrorDto {
                    error: String::from("An error occurred"),
                })
                .respond_to(&request)?,
            )
            .status(Status::InternalServerError)
            .ok(),
        }
    }
}

impl OpenApiResponder<'_> for Error {
    fn responses(gen: &mut OpenApiGenerator) -> rocket_okapi::Result<OAResponses> {
        let mut responses = OAResponses::default();
        let schema = gen.json_schema_no_ref::<ErrorDto>();
        add_schema_response(&mut responses, 401, "application/json", schema.clone())?;
        add_schema_response(&mut responses, 500, "application/json", schema)?;
        Ok(responses)
    }
}
