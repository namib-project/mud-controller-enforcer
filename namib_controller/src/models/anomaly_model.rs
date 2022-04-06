// Copyright 2022, Hannes Masuch
// SPDX-License-Identifier: MIT OR Apache-2.0

use chrono::NaiveDateTime;
use std::convert::TryFrom;
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
    pub l4protocol: Option<i64>,
    pub date_time_created: NaiveDateTime,
}

#[derive(Debug, Clone)]
pub struct Anomaly {
    pub id: i64,
    pub source_ip: IpAddr,
    pub source_port: Option<u16>,
    pub source_id: Option<i64>,
    pub destination_ip: IpAddr,
    pub destination_port: Option<u16>,
    pub destination_id: Option<i64>,
    pub l4protocol: Option<i32>,
    pub date_time_created: NaiveDateTime,
}

impl From<AnomalyDbo> for Anomaly {
    fn from(anomaly: AnomalyDbo) -> Self {
        Self {
            id: anomaly.id,
            source_ip: anomaly.source_ip.parse().unwrap(),
            source_port: match anomaly.source_port {
                Some(source_port) => u16::try_from(source_port).ok(),
                None => None,
            },
            source_id: anomaly.source_id,
            destination_ip: anomaly.destination_ip.parse().unwrap(),
            destination_port: match anomaly.destination_port {
                Some(destination_port) => u16::try_from(destination_port).ok(),
                None => None,
            },
            destination_id: anomaly.destination_id,
            l4protocol: match anomaly.l4protocol {
                Some(l4protocol) => i32::try_from(l4protocol).ok(),
                None => None,
            },
            date_time_created: anomaly.date_time_created,
        }
    }
}
