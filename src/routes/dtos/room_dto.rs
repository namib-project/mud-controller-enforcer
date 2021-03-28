#![allow(clippy::field_reassign_with_default)]

use crate::{error::Result, models::Room};
use paperclip::actix::Apiv2Schema;

#[derive(Validate, Debug, Serialize, Deserialize, Apiv2Schema, PartialEq)]
pub struct RoomDto {
    pub id: i64,
    #[validate(length(max = 50))]
    pub name: String,
    #[validate(length(max = 6))]
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

#[derive(Validate, Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct RoomCreationUpdateDto {
    #[validate(length(max = 50))]
    pub name: String,
    #[validate(length(max = 6))]
    pub color: String,
}

impl RoomCreationUpdateDto {
    pub fn to_room(&self, id: i64) -> Result<Room> {
        Ok(Room {
            room_id: id,
            name: self.name.clone(),
            color: self.color.clone(),
        })
    }
}
