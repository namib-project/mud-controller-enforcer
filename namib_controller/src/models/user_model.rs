// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::field_reassign_with_default)]

use argon2::{self, Config};
use chrono::NaiveDateTime;
use paperclip::actix::Apiv2Schema;
use rand::{rngs::OsRng, Rng};
use snafu::ensure;

use crate::{error, error::Result};

pub const SALT_LENGTH: usize = 32;

#[derive(Debug, Clone)]
pub struct UserDbo {
    pub id: i64,
    pub username: String,
    pub password: String,
    pub salt: Vec<u8>,
    pub last_interaction: NaiveDateTime,
    pub change_next_login: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Apiv2Schema)]
pub struct User {
    pub id: i64,
    pub username: String,
    #[serde(skip_serializing)]
    pub password: String,
    #[serde(skip_serializing)]
    pub salt: Vec<u8>,
    pub last_interaction: NaiveDateTime,
    pub roles: Vec<Role>,
    pub permissions: Vec<String>,
    #[serde(skip_serializing)]
    pub change_next_login: bool,
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize, Clone, Apiv2Schema)]
pub struct Role {
    pub id: i64,
    pub name: String,
}

impl From<RoleDbo> for Role {
    fn from(role: RoleDbo) -> Self {
        Self {
            id: role.id,
            name: role.name,
        }
    }
}

#[derive(Debug)]
pub struct RoleDbo {
    pub id: i64,
    pub name: String,
    pub permissions: String,
}

// Local methods
impl User {
    pub fn new(username: String, password: &str) -> Result<Self> {
        let salt = User::generate_salt();
        let utc_now = chrono::Utc::now().naive_utc();
        Ok(Self {
            id: 0,
            username,
            password: User::hash_password(password, &salt)?,
            salt,
            last_interaction: utc_now,
            roles: Vec::new(),
            permissions: Vec::new(),
            change_next_login: false,
        })
    }

    pub fn update_password(&mut self, password: &str) -> Result<()> {
        self.salt = User::generate_salt();
        self.password = User::hash_password(password, &self.salt)?;
        Ok(())
    }

    pub fn verify_password(&self, password: &str) -> Result<()> {
        let result = argon2::verify_encoded(self.password.as_ref(), password.as_ref())?;
        ensure!(result, error::PasswordVerifyError {});
        Ok(())
    }

    pub fn hash_password(password: &str, salt: &[u8]) -> Result<String> {
        let argon_config = Config::default();

        Ok(argon2::hash_encoded(password.as_bytes(), salt, &argon_config)?)
    }

    pub fn generate_salt() -> Vec<u8> {
        let mut salt = vec![0u8; SALT_LENGTH];
        OsRng::default().fill(salt.as_mut_slice());
        salt
    }
}
