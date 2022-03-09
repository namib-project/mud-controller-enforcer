// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{future::Future, pin::Pin};

use actix_web::{dev, error::ErrorUnauthorized, http::StatusCode, web, FromRequest, HttpRequest};
use chrono::{Duration, Utc};
use glob::Pattern;
use jsonwebtoken as jwt;
use paperclip::actix::Apiv2Security;
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    db::DbConnection,
    error,
    error::{Error::DatabaseError, Result},
    services::{
        config_service::{get_config_value, set_config_value},
        role_service::Permission,
        user_service,
    },
};

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
            if Pattern::new(perm)?.matches(permission.as_ref()) {
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
    pub async fn encode_token(&self, conn: &DbConnection) -> String {
        jwt::encode(
            &jwt::Header::default(),
            self,
            &get_config_value("jwt_secret", conn)
                .await
                .and_then(|s: String| jwt::EncodingKey::from_base64_secret(&s).map_err(std::convert::Into::into))
                .expect("env JWT_SECRET is not valid base64"),
        )
        .expect("jwt")
    }

    /// Decode token into "Auth" struct.
    pub async fn decode_token(token: &str, conn: &DbConnection) -> Option<AuthToken> {
        use jwt::{Algorithm, Validation};

        jwt::decode(
            token,
            &get_config_value("jwt_secret", conn)
                .await
                .and_then(|s: String| jwt::DecodingKey::from_base64_secret(&s).map_err(std::convert::Into::into))
                .expect("env JWT_SECRET is not valid base64"),
            &Validation::new(Algorithm::HS256),
        )
        .map_err(|err| {
            warn!("Auth decode error: {:?}", err);
        })
        .ok()
        .map(|token_data| token_data.claims)
    }
}

fn extract_token_from_header(header: &str) -> Option<&str> {
    header.strip_prefix(HEADER_PREFIX)
}

async fn extract_auth_from_request(conn: &DbConnection, request: &HttpRequest) -> Option<AuthToken> {
    let token = request
        .headers()
        .get("authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(extract_token_from_header);
    if let Some(token_str) = token {
        AuthToken::decode_token(token_str, conn).await
    } else {
        None
    }
}

impl FromRequest for AuthToken {
    type Config = ();
    type Error = actix_web::Error;
    type Future = Pin<Box<dyn Future<Output = std::result::Result<Self, Self::Error>>>>;

    /// Middleware for Auth struct extraction from "Authorization: Bearer {}" header.
    /// (Header => Token => Auth)
    ///
    /// If valid => success
    /// if invalid => will fail request with Unauthorized
    fn from_request(req: &HttpRequest, _payload: &mut dev::Payload) -> Self::Future {
        let req = req.clone();
        Box::pin(async move {
            let conn = req.app_data::<web::Data<DbConnection>>().unwrap();
            match extract_auth_from_request(conn, &req).await {
                Some(auth) => {
                    user_service::update_last_interaction_stamp(auth.sub, conn).await?;
                    Ok(auth)
                },
                None => Err(ErrorUnauthorized("Unauthorized")),
            }
        })
    }
}

pub async fn initialize_jwt_secret(conn: &DbConnection) -> Result<()> {
    let jwt_secret: Result<String> = get_config_value("jwt_secret", conn).await;
    match jwt_secret {
        Err(DatabaseError {
            source: sqlx::error::Error::RowNotFound,
            backtrace: _,
        }) => {
            let mut jwt_secret = [0; 256];
            thread_rng().fill_bytes(&mut jwt_secret);
            set_config_value("jwt_secret", base64::encode(&jwt_secret), conn).await?;
            Ok(())
        },
        x => x.map(|_v| ()),
    }
}
