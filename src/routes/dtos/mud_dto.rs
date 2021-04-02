use crate::models::Acl;
use paperclip::actix::Apiv2Schema;

#[derive(Deserialize, Apiv2Schema)]
pub struct MudQueryDto {
    pub mud_url: Option<String>,
}

#[derive(Deserialize, Apiv2Schema)]
pub struct MudUpdateQueryDto {
    pub mud_url: String,
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct MudCreationDto {
    pub mud_url: String,
    pub acl_override: Option<Vec<Acl>>,
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct MudUpdateDto {
    pub acl_override: Option<Vec<Acl>>,
}
