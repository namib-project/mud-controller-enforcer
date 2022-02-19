// Copyright 2022, Matthias Reichmann
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::field_reassign_with_default)]

use paperclip::actix::Apiv2Schema;

use crate::models::Floor;

#[derive(Validate, Debug, Serialize, Deserialize, Apiv2Schema, PartialEq)]
pub struct FloorDto {
    pub id: i64,
    #[validate(length(max = 128))]
    pub label: String,
}

impl From<Floor> for FloorDto {
    fn from(floor: Floor) -> Self {
        FloorDto {
            id: floor.id,
            label: floor.label,
        }
    }
}

#[derive(Validate, Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct FloorCreationUpdateDto {
    #[validate(length(max = 128))]
    pub label: String,
}

impl FloorCreationUpdateDto {
    pub fn into_floor(self, id: i64) -> Floor {
        Floor {
            id: id,
            label: self.label,
        }
    }
}
