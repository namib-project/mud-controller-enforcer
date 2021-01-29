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

#[derive(Serialize, Apiv2Schema)]
pub struct TokenDto {
    pub token: String,
}

#[derive(Serialize, Apiv2Schema)]
pub struct LoginResponseDto {
    pub access_token: TokenDto,
    pub refresh_token: TokenDto,
}

#[derive(Serialize, Apiv2Schema)]
pub struct SuccessDto {
    pub status: String,
}

#[derive(Serialize, Apiv2Schema)]
pub struct RoleDto {
    pub name: String,
    pub permissions: Vec<String>,
}
