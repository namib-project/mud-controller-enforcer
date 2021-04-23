use chrono::NaiveDateTime;
use paperclip::actix::Apiv2Schema;

#[derive(Debug, Apiv2Schema, Clone, Serialize)]
pub struct EnforcerDto {
    pub cert_id: String,
    pub last_ip_address: String,
    pub last_interaction: NaiveDateTime,
    pub allowed: bool,
}

#[derive(Deserialize, Apiv2Schema)]
pub struct EnforcerUpdateQuery {
    pub allowed: bool,
}
