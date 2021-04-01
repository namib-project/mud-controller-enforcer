#![allow(clippy::field_reassign_with_default)]

use crate::models::Role;
use paperclip::actix::Apiv2Schema;

#[derive(Validate, Serialize, Deserialize, Apiv2Schema)]
pub struct MgmUserDto {
    pub user_id: i64,
    #[validate(length(min = 1, max = 128))]
    pub username: String,
    pub roles: Vec<Role>,
    pub permissions: Vec<String>,
}

#[derive(Validate, Serialize, Deserialize, Apiv2Schema)]
pub struct MgmCreateUserDto {
    #[validate(length(min = 1, max = 128))]
    pub username: String,
    #[validate(length(min = 6))]
    pub password: String,
    pub roles_ids: Vec<i64>,
}

#[derive(Validate, Serialize, Deserialize, Apiv2Schema)]
pub struct MgmUpdateUserBasicDto {
    #[validate(length(min = 1, max = 128))]
    pub username: String,
    pub password: String,
}
