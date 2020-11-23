use std::env;

use chrono::{Duration, Utc};
use jsonwebtoken as jwt;
use rocket::{
    http::Status,
    request::{self, FromRequest, Request},
    Outcome,
};
use serde::{Deserialize, Serialize};

static HEADER_PREFIX: &str = "Bearer ";

#[derive(Clone, Deserialize, Serialize)]
pub struct Auth {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Subject
    pub sub: String,

    // User stuff
    pub id: i32,
    pub username: String,
}

impl Auth {
    pub fn generate_auth(id: i32, username: String, sub: String) -> Auth {
        let time_now = Utc::now().naive_utc();
        Auth {
            nbf: time_now.timestamp(),
            exp: (time_now + Duration::days(7)).timestamp(),
            sub,
            id,
            username,
        }
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
    pub fn decode_token(token: &str) -> Option<Auth> {
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

fn extract_auth_from_request(request: &Request) -> Option<Auth> {
    request
        .headers()
        .get_one("authorization")
        .and_then(extract_token_from_header)
        .and_then(|token| Auth::decode_token(token))
}

fn extract_token_from_header(header: &str) -> Option<&str> {
    header.strip_prefix(HEADER_PREFIX)
}

impl<'a, 'r> FromRequest<'a, 'r> for Auth {
    type Error = &'static str;

    /// Middleware for Auth struct extraction from "Authorization: Bearer {}" header.
    /// (Header => Token => Auth)
    ///
    /// If valid => success
    /// if invalid => will fail request with Unauthorized
    fn from_request(request: &'a Request<'r>) -> request::Outcome<Auth, Self::Error> {
        match extract_auth_from_request(request) {
            Some(auth) => Outcome::Success(auth),
            None => Outcome::Failure((Status::Forbidden, "Unauthorized")),
        }
    }
}
