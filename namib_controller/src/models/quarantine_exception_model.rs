// Copyright 2022, Hannes Masuch
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::models::AclDirection;
use crate::routes::dtos::QuarantineExceptionDto;

#[derive(Debug, Clone)]
pub struct QuarantineException {
    pub id: i64,
    pub exception_target: String,
    pub direction: AclDirection,
}

impl QuarantineException {
    pub fn into_dto(self, device_id: Option<i64>, mud_url: Option<String>) -> QuarantineExceptionDto {
        QuarantineExceptionDto {
            id: self.id,
            exception_target: self.exception_target,
            direction: self.direction.to_string(),
            device_id,
            mud_url,
        }
    }
}

#[derive(Debug, Clone)]
pub struct QuarantineExceptionDbo {
    pub id: i64,
    pub device_id: Option<i64>,
    pub exception_target: String,
    pub direction: i64,
    pub mud_url: Option<String>,
}

impl From<QuarantineExceptionDbo> for QuarantineException {
    fn from(exception: QuarantineExceptionDbo) -> Self {
        Self {
            id: exception.id,
            exception_target: exception.exception_target,
            direction: match exception.direction {
                0 => AclDirection::FromDevice,
                _ => AclDirection::ToDevice,
            },
        }
    }
}

impl From<QuarantineExceptionDbo> for QuarantineExceptionDto {
    fn from(exception: QuarantineExceptionDbo) -> Self {
        Self {
            id: exception.id,
            exception_target: exception.exception_target,
            direction: match exception.direction {
                0 => AclDirection::FromDevice.to_string(),
                1 => AclDirection::ToDevice.to_string(),
                _ => "undefined".to_string(),
            },
            device_id: exception.device_id,
            mud_url: exception.mud_url,
        }
    }
}
