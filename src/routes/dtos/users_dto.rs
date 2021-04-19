#![allow(clippy::field_reassign_with_default)]

use paperclip::actix::Apiv2Schema;

#[derive(Validate, Serialize, Deserialize, Apiv2Schema)]
pub struct SignupDto {
    #[validate(length(min = 1, max = 128))]
    pub username: String,
    #[validate(length(min = 6))]
    pub password: String,
}

#[derive(Validate, Serialize, Deserialize, Apiv2Schema)]
pub struct LoginDto {
    #[validate(length(min = 1, max = 128))]
    pub username: String,
    #[validate(length(min = 6))]
    pub password: String,
}

#[derive(Validate, Serialize, Deserialize, Apiv2Schema)]
pub struct UpdatePasswordDto {
    #[validate(length(min = 6))]
    pub old_password: String,
    #[validate(length(min = 6))]
    pub new_password: String,
}

#[derive(Validate, Serialize, Deserialize, Apiv2Schema)]
pub struct UpdateUserDto {
    #[validate(length(min = 1, max = 128))]
    pub username: Option<String>,
}

#[derive(Serialize, Deserialize, Apiv2Schema)]
pub struct TokenDto {
    pub token: String,
}

#[derive(Serialize, Deserialize, Apiv2Schema)]
pub struct SuccessDto {
    pub status: String,
}

#[derive(Validate, Serialize, Deserialize, Apiv2Schema, Debug, Clone)]
pub struct RoleDto {
    pub id: i64,
    pub name: String,
    pub permissions: Vec<String>,
}

#[derive(Validate, Serialize, Deserialize, Apiv2Schema, Debug, Clone)]
pub struct RoleUpdateDto {
    pub name: String,
    pub permissions: Vec<String>,
}
