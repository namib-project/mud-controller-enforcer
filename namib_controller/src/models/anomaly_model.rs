// Copyright 2022, Hannes Masuch
// SPDX-License-Identifier: MIT OR Apache-2.0

use chrono::NaiveDateTime;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct AnomalyDbo {
    pub id: i64,
    pub source_ip: String,
    pub source_port: Option<i64>,
    pub source_id: Option<i64>,
    pub destination_ip: String,
    pub destination_port: Option<i64>,
    pub destination_id: Option<i64>,
    pub protocol: String,
    pub date_time_created: NaiveDateTime,
}

#[derive(Debug, Clone)]
pub struct Anomaly {
    pub id: i64,
    pub source_ip: IpAddr,
    pub source_port: Option<i64>,
    pub source_id: Option<i64>,
    pub destination_ip: IpAddr,
    pub destination_port: Option<i64>,
    pub destination_id: Option<i64>,
    pub protocol: String,
    pub date_time_created: NaiveDateTime,
}

impl From<AnomalyDbo> for Anomaly {
    fn from(anomaly: AnomalyDbo) -> Self {
        Self {
            id: anomaly.id,
            source_ip: anomaly.source_ip.parse().unwrap(),
            source_port: anomaly.source_port,
            source_id: anomaly.source_id,
            destination_ip: anomaly.destination_ip.parse().unwrap(),
            destination_port: anomaly.destination_port,
            destination_id: anomaly.destination_id,
            protocol: anomaly.protocol,
            date_time_created: anomaly.date_time_created,
        }
    }
}
