#![allow(clippy::field_reassign_with_default)]

use crate::models::{Device, MudData, Room};
use paperclip::actix::Apiv2Schema;

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct RoomDto {
    pub id: i64,
    pub name: String,
    pub color: String,
}

impl From<Room> for RoomDto {
    fn from(room: Room) -> Self {
        RoomDto {
            id: room.room_id,
            name: room.name,
            color: room.color,
        }
    }
}
