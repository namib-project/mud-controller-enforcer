use chrono::NaiveDateTime;

#[derive(Debug, Clone)]
pub struct DeviceConnections {
    pub device_id: i64,
    pub from: Vec<DeviceConnection>,
    pub to: Vec<DeviceConnection>,
}

#[derive(Debug, Clone)]
pub struct DeviceConnection {
    pub date: NaiveDateTime,
    pub target: String,
    pub amount: i64,
}
