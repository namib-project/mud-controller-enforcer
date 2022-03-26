// Copyright 2022, Matthias Reichmann
// SPDX-License-Identifier: MIT OR Apache-2.0

use paperclip::actix::Apiv2Schema;
use std::{
    ops::Deref,
};
use chrono::NaiveDateTime;
use crate::{
    db::DbConnection,
    error::Result,
    models::{Device},
    services::{device_service},
};
use crate::models::DeviceWithRefs;

#[derive(Debug, Clone)]
pub struct Notification {
    pub id: i64,
    pub device_id: i64,
    pub source: String,
    pub timestamp: NaiveDateTime,
    pub read: bool,
}

#[derive(Debug, Clone)]
pub struct NotificationWithRefs {
    pub inner: Notification,
    pub device: DeviceWithRefs,
}

impl Deref for NotificationWithRefs {
    type Target = Notification;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Notification {
    pub async fn load_refs(self, conn: &DbConnection) -> Result<NotificationWithRefs> {
        let device = device_service::find_by_id(self.device_id, conn).await?;
        let device_with_refs = device.load_refs(conn).await?;

        Ok(NotificationWithRefs {
            inner: self,
            device: device_with_refs,
        })
    }
}
