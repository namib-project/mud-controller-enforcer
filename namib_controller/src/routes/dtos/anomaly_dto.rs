// Copyright 2022, Hannes Masuch
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{error::Result, models::Anomaly};
use chrono::NaiveDateTime;
use paperclip::actix::Apiv2Schema;

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct AnomalyDto {
    pub id: i64,
    pub source_ip: String,
    pub source_port: Option<u16>,
    pub source_id: Option<i64>,
    pub destination_ip: String,
    pub destination_port: Option<u16>,
    pub destination_id: Option<i64>,
    pub l4protocol: Option<i32>,
    pub date_time_created: NaiveDateTime,
}

impl From<&Anomaly> for AnomalyDto {
    fn from(anomaly: &Anomaly) -> Self {
        Self {
            id: anomaly.id,
            source_ip: anomaly.source_ip.to_string(),
            source_port: anomaly.source_port,
            source_id: anomaly.source_id,
            destination_ip: anomaly.destination_ip.to_string(),
            destination_port: anomaly.destination_port,
            destination_id: anomaly.destination_id,
            l4protocol: anomaly.l4protocol,
            date_time_created: anomaly.date_time_created,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct AnomalyCreationDto {
    pub source_ip: String,
    pub source_port: Option<u16>,
    pub source_id: Option<i64>,
    pub destination_ip: String,
    pub destination_port: Option<u16>,
    pub destination_id: Option<i64>,
    pub l4protocol: Option<i32>,
}

impl AnomalyCreationDto {
    pub fn into_anomaly(&self, id: i64, date_time_created: NaiveDateTime) -> Result<Anomaly> {
        Ok(Anomaly {
            id,
            source_ip: self.source_ip.parse().ok().unwrap(),
            source_port: self.source_port,
            source_id: self.source_id,
            destination_ip: self.destination_ip.parse().ok().unwrap(),
            destination_port: self.destination_port,
            destination_id: self.destination_id,
            l4protocol: self.l4protocol,
            date_time_created,
        })
    }
}