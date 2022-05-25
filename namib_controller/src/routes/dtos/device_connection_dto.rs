use crate::models::{DeviceConnection, DeviceConnections};
use paperclip::actix::Apiv2Schema;

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct DeviceConnectionsDto {
    pub device_id: i64,
    pub from: Vec<DeviceConnectionDto>,
    pub to: Vec<DeviceConnectionDto>,
}

impl From<&DeviceConnections> for DeviceConnectionsDto {
    fn from(conn: &DeviceConnections) -> Self {
        Self {
            device_id: conn.device_id,
            from: conn.from.iter().map(DeviceConnectionDto::from).collect(),
            to: conn.to.iter().map(DeviceConnectionDto::from).collect(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct DeviceConnectionDto {
    pub target: String,
    pub amount: i64,
}

impl From<&DeviceConnection> for DeviceConnectionDto {
    fn from(conn: &DeviceConnection) -> Self {
        Self {
            target: conn.target.to_string(),
            amount: conn.amount,
        }
    }
}
