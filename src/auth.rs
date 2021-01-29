use std::env;

use crate::error::{ResponseError, Result};
use actix_web::{dev, error::ErrorUnauthorized, FromRequest, HttpRequest};
use chrono::{Duration, Utc};
use futures::{future, future::Ready};
use glob::Pattern;
use isahc::http::StatusCode;
use jsonwebtoken as jwt;
use paperclip::actix::Apiv2Security;
use serde::{Deserialize, Serialize};

static HEADER_PREFIX: &str = "Bearer ";

#[derive(Apiv2Security, Clone, Deserialize, Serialize)]
#[openapi(apiKey, in = "header", name = "Authorization")]
pub struct AuthAccess {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // User Id
    pub sub: i64,

    // User stuff
    pub username: String,
    pub permissions: Vec<String>,
}

#[derive(Apiv2Security, Clone, Deserialize, Serialize)]
#[openapi(apiKey, in = "header", name = "Authorization")]
pub struct AuthRefresh {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // User Id
    pub sub: i64,

    // Session refresh stuff
    pub refresh_token: String,
}

impl AuthAccess {
    pub fn generate_access_token(id: i64, username: String, permissions: Vec<String>) -> AuthAccess {
        let time_now = Utc::now().naive_utc();
        AuthAccess {
            nbf: time_now.timestamp(),
            exp: (time_now + Duration::minutes(15)).timestamp(),
            sub: id,
            username,
            permissions,
        }
    }

    pub fn require_permission(&self, permission: &str) -> Result<()> {
        for perm in &self.permissions {
            if Pattern::new(perm)?.matches(permission) {
                return Ok(());
            }
        }
        ResponseError {
            status: StatusCode::FORBIDDEN,
            message: Some("Forbidden".to_string()),
        }
        .fail()?
    }

    /// Encodes "Auth" struct to JWT token
    pub fn encode_token(&self) -> String {
        jwt::encode(
            &jwt::Header::default(),
            self,
            &jwt::EncodingKey::from_secret(
                env::var("JWT_ACCESS_TOKEN_SECRET")
                    .expect("JWT_ACCESS_TOKEN_SECRET must be set")
                    .as_ref(),
            ),
        )
        .expect("jwt")
    }

    /// Decode token into "Auth" struct.
    pub fn decode_token(token: &str) -> Option<AuthAccess> {
        use jwt::{Algorithm, Validation};

        jwt::decode(
            token,
            &jwt::DecodingKey::from_secret(
                env::var("JWT_ACCESS_TOKEN_SECRET")
                    .expect("JWT_ACCESS_TOKEN_SECRET must be set")
                    .as_ref(),
            ),
            &Validation::new(Algorithm::HS256),
        )
        .map_err(|err| {
            eprintln!("Auth decode error: {:?}", err);
        })
        .ok()
        .map(|token_data| token_data.claims)
    }
}

impl AuthRefresh {
    pub fn generate_refresh_token(id: i64, refresh_token: String) -> AuthRefresh {
        let time_now = Utc::now().naive_utc();
        AuthRefresh {
            nbf: time_now.timestamp(),
            exp: (time_now + Duration::days(7)).timestamp(),
            sub: id,
            refresh_token,
        }
    }

    /// Encodes "Auth" struct to JWT token
    pub fn encode_token(&self) -> String {
        jwt::encode(
            &jwt::Header::default(),
            self,
            &jwt::EncodingKey::from_secret(
                env::var("JWT_REFRESH_TOKEN_SECRET")
                    .expect("JWT_REFRESH_TOKEN_SECRET must be set")
                    .as_ref(),
            ),
        )
        .expect("jwt")
    }

    /// Decode token into "Auth" struct.
    pub fn decode_token(token: &str) -> Option<AuthRefresh> {
        use jwt::{Algorithm, Validation};

        jwt::decode(
            token,
            &jwt::DecodingKey::from_secret(
                env::var("JWT_REFRESH_TOKEN_SECRET")
                    .expect("JWT_REFRESH_TOKEN_SECRET must be set")
                    .as_ref(),
            ),
            &Validation::new(Algorithm::HS256),
        )
        .map_err(|err| {
            eprintln!("Auth decode error: {:?}", err);
        })
        .ok()
        .map(|token_data| token_data.claims)
    }
}

fn extract_token_from_header(header: &str) -> Option<&str> {
    header.strip_prefix(HEADER_PREFIX)
}

fn extract_auth_from_request(request: &HttpRequest) -> Option<AuthAccess> {
    request
        .headers()
        .get("authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(extract_token_from_header)
        .and_then(|token| AuthAccess::decode_token(token))
}

impl FromRequest for AuthAccess {
    type Config = ();
    type Error = actix_web::Error;
    type Future = Ready<std::result::Result<Self, Self::Error>>;

    /// Middleware for Auth struct extraction from "Authorization: Bearer {}" header.
    /// (Header => Token => Auth)
    ///
    /// If valid => success
    /// if invalid => will fail request with Unauthorized
    fn from_request(req: &HttpRequest, _payload: &mut dev::Payload) -> Self::Future {
        match extract_auth_from_request(req) {
            Some(auth) => future::ok(auth),
            None => future::err(ErrorUnauthorized("Unauthorized")),
        }
    }
}

fn extract_auth_refresh_from_request(request: &HttpRequest) -> Option<AuthRefresh> {
    request
        .headers()
        .get("authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(extract_token_from_header)
        .and_then(|token| AuthRefresh::decode_token(token))
}

impl FromRequest for AuthRefresh {
    type Config = ();
    type Error = actix_web::Error;
    type Future = Ready<std::result::Result<Self, Self::Error>>;

    /// Middleware for Auth struct extraction from "Authorization: Bearer {}" header.
    /// (Header => Token => Auth)
    ///
    /// If valid => success
    /// if invalid => will fail request with Unauthorized
    fn from_request(req: &HttpRequest, _payload: &mut dev::Payload) -> Self::Future {
        match extract_auth_refresh_from_request(req) {
            Some(auth) => future::ok(auth),
            None => future::err(ErrorUnauthorized("Unauthorized")),
        }
    }
}
