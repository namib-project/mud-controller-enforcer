// Copyright 2022, Hannes Masuch
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::field_reassign_with_default)]

use crate::models::{AclDirection, QuarantineException};
use paperclip::actix::Apiv2Schema;

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct QuarantineExceptionDto {
    pub id: i64,
    pub exception_target: String,
    pub direction: String,
    pub device_id: i64,
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct QuarantineExceptionCreationUpdateDto {
    pub exception_target: Option<String>,
    pub direction: Option<String>,
    pub device_id: Option<i64>,
}

impl From<QuarantineExceptionCreationUpdateDto> for QuarantineException {
    fn from(e: QuarantineExceptionCreationUpdateDto) -> Self {
        QuarantineException {
            id: 0,
            exception_target: e.exception_target.unwrap_or_else(|| "".to_string()),
            direction: match e.direction.unwrap().as_str() {
                "FromDevice" => AclDirection::FromDevice,
                _ => AclDirection::ToDevice,
            },
        }
    }
}

impl QuarantineExceptionCreationUpdateDto {
    pub fn apply(self, exception: &mut QuarantineException) {
        if let Some(exception_target) = self.exception_target {
            exception.exception_target = exception_target;
        }
        if let Some(direction) = self.direction {
            exception.direction = match direction.as_str() {
                "FromDevice" => AclDirection::FromDevice,
                "ToDevice" => AclDirection::ToDevice,
                _ => exception.direction,
            };
        }
    }
}
