#![allow(clippy::field_reassign_with_default)]

use paperclip::actix::Apiv2Schema;

#[derive(Validate, Serialize, Deserialize, Apiv2Schema)]
pub struct UserConfigsDto {
    #[validate(length(max = 40))]
    pub activated_theme: String,
}

impl UserConfigsDto {
    pub(crate) fn get_fields() -> Vec<String> {
        // TODO: Make this vec dynamic with trait + macro.
        vec!["activated_theme".to_string()]
    }
}
