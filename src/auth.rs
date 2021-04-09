use std::env;

use crate::{
    db::DbConnection,
    error,
    error::{Error, Result},
    services::{role_service::Permission, user_service},
};
use actix_web::{dev, error::ErrorUnauthorized, web, FromRequest, HttpRequest};
use chrono::{Duration, Utc};
use futures::{future, future::Ready};
use glob::Pattern;
use isahc::http::StatusCode;
use jsonwebtoken as jwt;
use paperclip::actix::Apiv2Security;
use serde::{Deserialize, Serialize};

static HEADER_PREFIX: &str = "Bearer ";

#[derive(Apiv2Security, Clone, Deserialize, Serialize)]
#[openapi(
    apiKey,
    in = "header",
    name = "Authorization",
    description = "Use format: 'Bearer JWT_TOKEN'"
)]
pub struct AuthToken {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // User Id
    pub sub: i64,

    // User stuff
    pub username: String,
    // TODO: Obsolete?
    pub permissions: Vec<String>,
}

impl AuthToken {
    pub fn generate_access_token(id: i64, username: String, permissions: Vec<String>) -> AuthToken {
        let time_now = Utc::now().naive_utc();
        AuthToken {
            nbf: time_now.timestamp(),
            exp: (time_now + Duration::minutes(15)).timestamp(),
            sub: id,
            username,
            permissions,
        }
    }

    pub fn require_permission(&self, permission: Permission) -> Result<()> {
        for perm in &self.permissions {
            if Pattern::new(perm)?.matches(&*permission.to_string()) {
                return Ok(());
            }
        }
        error::ResponseError {
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
            &jwt::EncodingKey::from_secret(env::var("JWT_SECRET").expect("JWT_SECRET must be set").as_ref()),
        )
        .expect("jwt")
    }

    /// Decode token into "Auth" struct.
    pub fn decode_token(token: &str) -> Option<AuthToken> {
        use jwt::{Algorithm, Validation};

        jwt::decode(
            token,
            &jwt::DecodingKey::from_secret(env::var("JWT_SECRET").expect("JWT_SECRET must be set").as_ref()),
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

fn extract_auth_from_request(request: &HttpRequest) -> Option<AuthToken> {
    request
        .headers()
        .get("authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(extract_token_from_header)
        .and_then(|token| AuthToken::decode_token(token))
}

impl FromRequest for AuthToken {
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
            Some(auth) => {
                let pool = req.app_data::<web::Data<DbConnection>>().unwrap();
                let runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
                match runtime.block_on(user_service::update_last_interaction_stamp(auth.sub, pool)) {
                    Ok(_) => {},
                    Err(_) => {},
                }
                return future::ok(auth);
            },
            None => future::err(ErrorUnauthorized("Unauthorized")),
        }
    }
}
