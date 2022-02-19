// Copyright 2020-2022, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach, Matthias Reichmann
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::field_reassign_with_default)]

use paperclip::actix::Apiv2Schema;

use crate::models::Room;

#[derive(Validate, Debug, Serialize, Deserialize, Apiv2Schema, PartialEq)]
pub struct RoomDto {
    pub id: i64,
    pub floor_id: i64,
    #[validate(length(max = 50))]
    pub number: String,
    #[validate(length(max = 255))]
    pub guest: Option<String>,
}

impl From<Room> for RoomDto {
    fn from(room: Room) -> Self {
        RoomDto {
            id: room.room_id,
            floor_id: room.floor_id,
            number: room.number,
            guest: room.guest,
        }
    }
}

#[derive(Validate, Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct RoomCreationUpdateDto {
    pub floor_id: i64,
    #[validate(length(max = 50))]
    pub number: String,
    #[validate(length(max = 255))]
    pub guest: Option<String>,
}

impl RoomCreationUpdateDto {
    pub fn into_room(self, id: i64) -> Room {
        Room {
            room_id: id,
            floor_id: self.floor_id,
            number: self.number,
            guest: self.guest,
        }
    }
}
