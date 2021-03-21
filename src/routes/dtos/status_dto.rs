use paperclip::actix::Apiv2Schema;

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct StatusDto {
    pub setup_required: bool,
    pub version: &'static str,
    pub secure_name: Option<String>,
}
