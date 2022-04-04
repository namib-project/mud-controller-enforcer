// Copyright 2022, Matthias Reichmann
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::field_reassign_with_default)]

use chrono::NaiveDateTime;
use paperclip::actix::Apiv2Schema;

use crate::models::Notification;
use crate::models::NotificationWithRefs;
use crate::routes::dtos::DeviceDto;

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct NotificationDto {
    pub id: i64,
    pub device: DeviceDto,
    pub source: String,
    pub timestamp: NaiveDateTime,
    pub read: bool,
}

impl From<NotificationWithRefs> for NotificationDto {
    fn from(notification: NotificationWithRefs) -> Self {
        let source = String::from(notification.source.as_str());
        Self {
            id: notification.id,
            device: DeviceDto::from(notification.device.clone()),
            source,
            timestamp: notification.timestamp,
            read: notification.read,
        }
    }
}

#[derive(Validate, Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct NotificationCreationDto {
    pub device_id: i64,
    pub source: String,
    pub timestamp: NaiveDateTime,
    pub read: Option<bool>,
}

impl From<NotificationCreationDto> for Notification {
    fn from(creation: NotificationCreationDto) -> Self {
        Notification {
            id: 0,
            device_id: creation.device_id,
            source: creation.source,
            timestamp: creation.timestamp,
            read: creation.read.unwrap_or(false),
        }
    }
}
