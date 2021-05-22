// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::field_reassign_with_default)]

use paperclip::actix::Apiv2Schema;

use crate::models::Room;

#[derive(Validate, Debug, Serialize, Deserialize, Apiv2Schema, PartialEq)]
pub struct RoomDto {
    pub id: i64,
    #[validate(length(max = 50))]
    pub name: String,
    #[validate(length(max = 10))]
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
    #[validate(length(max = 10))]
    pub color: String,
}

impl RoomCreationUpdateDto {
    pub fn into_room(self, id: i64) -> Room {
        Room {
            room_id: id,
            name: self.name,
            color: self.color,
        }
    }
}
