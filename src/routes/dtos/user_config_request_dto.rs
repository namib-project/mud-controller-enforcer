#![allow(clippy::field_reassign_with_default)]

use paperclip::actix::Apiv2Schema;

#[derive(Validate, Serialize, Deserialize, Apiv2Schema)]
pub struct UserConfigRequestDto {
    pub key: String,
}
