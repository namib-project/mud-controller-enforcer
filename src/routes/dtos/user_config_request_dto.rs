#![allow(clippy::field_reassign_with_default)]

use paperclip::actix::Apiv2Schema;

#[derive(Validate, Serialize, Deserialize, Apiv2Schema)]
pub struct UserConfigRequestDto {
    #[validate(length(min = 1, max = 40))]
    pub key: String,
}
