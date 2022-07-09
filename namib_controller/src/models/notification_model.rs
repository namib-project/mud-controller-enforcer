// Copyright 2022, Matthias Reichmann, Hannes Masuch
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::models::{AnomalyDbo, DeviceWithRefs};
use crate::{db::DbConnection, error::Result, services::device_service};
use chrono::{NaiveDateTime, Utc};
use std::ops::Deref;

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

impl From<AnomalyDbo> for Notification {
    fn from(anomaly: AnomalyDbo) -> Self {
        Self {
            id: 0,
            device_id: match (anomaly.source_id, anomaly.destination_id) {
                (None, Some(dest_id)) => dest_id,
                (Some(src_id), _) => src_id,
                (None, None) => 0,
            },
            source: "MUD file violation detection".to_string(),
            timestamp: Utc::now().naive_local(),
            read: false,
        }
    }
}
