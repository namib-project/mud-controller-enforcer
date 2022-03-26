// Copyright 2022, Matthias Reichmann
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::field_reassign_with_default)]

use chrono::NaiveDateTime;
use paperclip::actix::Apiv2Schema;

use crate::{
    error::Result,
    models::{NotificationWithRefs, Device},
    routes::dtos::DeviceDto,
};
use crate::models::Notification;

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
        NotificationDto {
            id: notification.id,
            device: DeviceDto::from(notification.device),
            source: notification.source.clone(),
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

impl NotificationCreationDto {
    pub fn into_notification(self) -> Notification {
        Notification {
            id: 0,
            device_id: self.device_id,
            source: self.source,
            timestamp: self.timestamp,
            read: self.read.unwrap_or(false),
        }
    }
}
