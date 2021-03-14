use crate::models::Acl;
use paperclip::actix::Apiv2Schema;

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct MudCreationDto {
    pub mud_url: String,
    pub acl_override: Option<Vec<Acl>>,
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct MudUpdateDto {
    pub acl_override: Option<Vec<Acl>>,
}
