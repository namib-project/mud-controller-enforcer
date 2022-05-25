use std::str::FromStr;

use namib_shared::flow_scope::FlowData;
use namib_shared::flow_scope::FlowDataDirection;

use crate::db::DbConnection;
use crate::error::Result;
use crate::models::Device;
use crate::models::DeviceConnection;
use crate::models::DeviceConnections;
use crate::models::Level;

use super::device_service;
use super::flow_scope_service;

pub fn match_scope_level(level: &Level, data: &FlowData) -> bool {
    match level {
        Level::Full => data.packet != None,
        Level::HeadersOnly => data.packet == None,
    }
}

pub async fn on_flow(flow: &FlowData, pool: &DbConnection) -> Result<()> {
    if let Ok(device) = device_service::find_by_ip(flow.src_ip.to_string().as_str(), pool).await {
        for flow_scope in flow_scope_service::get_active_flow_scopes_for_device(pool, device.id)
            .await?
            .iter()
            .filter(|scope| match_scope_level(&scope.level, flow))
        {
            if flow_scope.name.contains("device_connections") {
                add_device_connection(&device, flow, pool).await?;
            }
        }
    }
    Ok(())
}

pub async fn add_device_connection(device: &Device, flow: &FlowData, pool: &DbConnection) -> Result<()> {
    let direction = flow.direction as i64;
    let dest_ip = flow.dest_ip.to_string();

    let _ = sqlx::query!(
        "INSERT OR IGNORE INTO device_connections (device_id, direction, target, amount) VALUES (?, ?, ?, 1);
         UPDATE device_connections SET amount = amount + 1 WHERE device_id = ? AND direction = ? AND target = ?",
        device.id,
        direction,
        dest_ip,
        device.id,
        direction,
        dest_ip,
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_device_connections(device: i64, pool: &DbConnection) -> Result<DeviceConnections> {
    let from_device = FlowDataDirection::FromDevice as i64;
    let to_device = FlowDataDirection::ToDevice as i64;

    Ok(DeviceConnections {
        device_id: device,
        from: sqlx::query!(
            "SELECT target, amount FROM device_connections WHERE device_id = ? AND direction = ?",
            device,
            from_device
        )
        .fetch_all(pool)
        .await?
        .iter()
        .map(|dbo| DeviceConnection {
            target: std::net::IpAddr::from_str(dbo.target.as_str()).unwrap(),
            amount: dbo.amount,
        })
        .collect(),
        to: sqlx::query!(
            "SELECT target, amount FROM device_connections WHERE device_id = ? AND direction = ?",
            device,
            to_device
        )
        .fetch_all(pool)
        .await?
        .iter()
        .map(|dbo| DeviceConnection {
            target: std::net::IpAddr::from_str(dbo.target.as_str()).unwrap(),
            amount: dbo.amount,
        })
        .collect(),
    })
}
