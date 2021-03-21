use paperclip::actix::Apiv2Schema;

#[derive(Debug, Clone, Serialize, Deserialize, Apiv2Schema)]
pub struct Room {
    pub room_id: i64,
    pub name: String,
    pub color: String,
}
