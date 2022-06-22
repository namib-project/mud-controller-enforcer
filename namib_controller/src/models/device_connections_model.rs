use chrono::NaiveDate;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct DeviceConnections {
    pub device_id: i64,
    pub from: Vec<DeviceConnection>,
    pub to: Vec<DeviceConnection>,
}

#[derive(Debug, Clone)]
pub struct DeviceConnection {
    pub date: NaiveDate,
    pub target: IpAddr,
    pub amount: i64,
}
