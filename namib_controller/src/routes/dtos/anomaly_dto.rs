// Copyright 2020-2022, Hannes Masuch
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{error::Result, models::Anomaly};
use chrono::{Duration, NaiveDateTime, Utc};
use paperclip::actix::Apiv2Schema;

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct AnomalyDto {
    pub id: i64,
    pub source_ip: Option<String>,
    pub source_port: Option<i64>,
    pub source_id: Option<i64>,
    pub destination_ip: Option<String>,
    pub destination_port: Option<i64>,
    pub destination_id: Option<i64>,
    pub protocol: Option<String>,
    pub date_time_created: NaiveDateTime,
}

impl From<&Anomaly> for AnomalyDto {
    fn from(anomaly: &Anomaly) -> Self {
        Self {
            id: anomaly.id,
            source_ip: Option::from(anomaly.source_ip.to_string()),
            source_port: anomaly.source_port,
            source_id: anomaly.source_id,
            destination_ip: Option::from(anomaly.destination_ip.to_string()),
            destination_port: anomaly.destination_port,
            destination_id: anomaly.destination_id,
            protocol: Option::from(anomaly.clone().protocol),
            date_time_created: anomaly.date_time_created,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct AnomalyCreationDto {
    pub source_ip: Option<String>,
    pub source_port: Option<i64>,
    pub source_id: Option<i64>,
    pub destination_ip: Option<String>,
    pub destination_port: Option<i64>,
    pub destination_id: Option<i64>,
    pub protocol: Option<String>,
    pub date_time_created: Option<NaiveDateTime>,
}

impl AnomalyCreationDto {
    pub fn into_anomaly(&self, id: i64) -> Result<Anomaly> {
        Ok(Anomaly {
            id,
            source_ip: self.source_ip.as_ref().unwrap().parse().unwrap(),
            source_port: self.source_port,
            source_id: self.source_id,
            destination_ip: self.destination_ip.as_ref().unwrap().parse().unwrap(),
            destination_port: self.destination_port,
            destination_id: self.destination_id,
            protocol: self.protocol.as_ref().unwrap().clone(),
            date_time_created: self
                .date_time_created
                .unwrap_or_else(|| Utc::now().naive_utc() + Duration::hours(1)),
        })
    }
}
