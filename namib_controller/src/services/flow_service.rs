use namib_shared::flow_scope::FlowData;
use namib_shared::flow_scope::FlowDataDirection;

use crate::db::DbConnection;
use crate::error::Result;
use crate::models::Device;
use crate::models::DeviceConnection;
use crate::models::DeviceConnections;
use crate::models::FlowScope;
use crate::models::FlowScopeLevel;

use super::device_service;
use super::flow_scope_service;

pub async fn on_device(pool: &DbConnection, device: Device) {
    if let Some(mac_addr) = device.mac_addr {
        let scope = if let Ok(id) = flow_scope_service::find_id_by_name(pool, "device_connections").await {
            id
        } else {
            flow_scope_service::insert_flow_scope(
                vec![],
                &FlowScope {
                    name: "device_connections".into(),
                    level: FlowScopeLevel::HeadersOnly,
                    ttl: 315_360_000, // 10 years, this should be changed to infinite.
                    starts_at: chrono::Utc::now().naive_local(),
                },
                pool,
            )
            .await
            .unwrap()
        };

        if let Err(e) = flow_scope_service::insert_targets(vec![mac_addr], scope, pool).await {
            warn!("Error inserting new device into flow scope: {:?}", e);
        }
    }
}

pub fn match_scope_level(level: &FlowScopeLevel, data: &FlowData) -> bool {
    match level {
        FlowScopeLevel::Full => data.packet != None,
        FlowScopeLevel::HeadersOnly => data.packet == None,
    }
}

pub async fn on_flow(flow: &FlowData, pool: &DbConnection) -> Result<()> {
    if let Ok(device) = device_service::find_by_ip(flow.device_ip().to_string().as_str(), pool).await {
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
    let dest_ip = flow.target_ip().to_string();

    // sqlx's sqlite backend does not support datetime, so we have to do some ugly conversion
    let date: chrono::NaiveDateTime = chrono::Utc::now().naive_local().date().and_hms(0, 0, 0);

    let _ = sqlx::query!(
        "INSERT INTO device_connections (device_id, date, direction, target, amount) VALUES ($1, $2, $3, $4, 0) ON CONFLICT DO NOTHING",
        device.id,
        date,
        direction,
        dest_ip,
    )
    .execute(pool)
    .await?;

    let _ = sqlx::query!(
         "UPDATE device_connections SET amount = amount + 1 WHERE device_id = $1 AND direction = $2 AND target = $3 AND date = $4",
        device.id,
        direction,
        dest_ip,
        date,
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
        from: sqlx::query_as!(
            DeviceConnection,
            "SELECT date, target, amount FROM device_connections WHERE device_id = $1 AND direction = $2",
            device,
            from_device
        )
        .fetch_all(pool)
        .await?,
        to: sqlx::query_as!(
            DeviceConnection,
            "SELECT date, target, amount FROM device_connections WHERE device_id = $1 AND direction = $2",
            device,
            to_device
        )
        .fetch_all(pool)
        .await?,
    })
}
