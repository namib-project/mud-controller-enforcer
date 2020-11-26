#![allow(clippy::field_reassign_with_default)]

use std::str::Split;

use argon2::{self, Config};
use rand::{rngs::OsRng, Rng};
use schemars::JsonSchema;
use snafu::ensure;

use crate::{
    error::{PasswordVerifyError, Result},
    schema::{roles, users, users_roles},
};

const SALT_LENGTH: usize = 32;

#[derive(Queryable, Identifiable, AsChangeset, Serialize, Deserialize, Clone, JsonSchema)]
#[table_name = "users"]
pub struct User {
    pub id: i32,
    pub username: String,
    #[serde(skip_serializing)]
    pub password: String,
    #[serde(skip_serializing)]
    pub salt: Vec<u8>,
}

#[derive(Identifiable, Queryable, Associations, Serialize, Deserialize, Clone)]
#[belongs_to(User)]
#[belongs_to(Role)]
#[table_name = "users_roles"]
pub struct UserRole {
    pub id: i32,
    pub user_id: i32,
    pub role_id: i32,
}

#[derive(Identifiable, Queryable, Serialize, Deserialize, Clone)]
#[table_name = "roles"]
pub struct Role {
    pub id: i32,
    pub name: String,
    pub permissions: String,
}

// Local methods
impl User {
    pub fn new(username: String, password: &str) -> Result<Self> {
        let mut salt = vec![0u8; SALT_LENGTH];
        OsRng::default().fill(salt.as_mut_slice());

        Ok(Self {
            id: 0,
            username,
            password: User::hash_password(password, &salt)?,
            salt,
        })
    }

    pub fn verify_password(&self, password: &str) -> Result<()> {
        let result = argon2::verify_encoded(self.password.as_ref(), password.as_ref())?;
        ensure!(result, PasswordVerifyError {});
        Ok(())
    }

    pub fn hash_password(password: &str, salt: &[u8]) -> Result<String> {
        let argon_config = Config::default();

        Ok(argon2::hash_encoded(password.as_bytes(), salt, &argon_config)?)
    }
}

impl Role {
    pub fn permissions(&self) -> Split<char> {
        self.permissions.split(',')
    }
}
