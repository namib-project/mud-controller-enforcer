// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use chrono::{Duration, Utc};
use namib_shared::flow_scope::FlowScope;

use crate::{
    db::DbConnection,
    error::Result,
    models::{FlowScopeDbo, LevelDbo},
    services::device_service,
};

///returns all flow scopes from the database
pub async fn get_all_flow_scopes(pool: &DbConnection) -> Result<Vec<FlowScopeDbo>> {
    let flowscopes = sqlx::query_as!(
        FlowScopeDbo,
        "SELECT id, name, level as \"level!: LevelDbo\", ttl, starts_at FROM flow_scopes"
    )
    .fetch_all(pool)
    .await?;
    Ok(flowscopes)
}

///returns all currently active flow scopes from the database
pub async fn get_active_flow_scopes(pool: &DbConnection) -> Result<Vec<FlowScopeDbo>> {
    let flowscopes = get_all_flow_scopes(pool).await?;
    let now = Utc::now().naive_utc();

    let active_flowscopes: Vec<FlowScopeDbo> = flowscopes
        .into_iter()
        .filter(|fs| (fs.starts_at < now && now < fs.starts_at.checked_add_signed(Duration::seconds(fs.ttl)).unwrap()))
        .collect();

    Ok(active_flowscopes)
}

///returns all flow scopes by name from the database
pub async fn find_by_name(pool: &DbConnection, name: &String) -> Result<FlowScopeDbo> {
    let flowscope = sqlx::query_as!(
        FlowScopeDbo,
        "SELECT id, name, level as \"level!: LevelDbo\", ttl, starts_at FROM flow_scopes WHERE name = ?",
        name
    )
    .fetch_one(pool)
    .await?;
    Ok(flowscope)
}

pub async fn insert_flow_scope(scope: &FlowScope, pool: &DbConnection) -> Result<u64> {
    let level: LevelDbo = LevelDbo::from(scope.level.clone());
    let insert = sqlx::query!(
        "INSERT INTO flow_scopes (name, level, ttl, starts_at) values ($1, $2, $3, $4)",
        scope.name,
        level,
        scope.ttl,
        scope.starts_at
    )
    .execute(pool)
    .await?;

    insert_targets(scope, insert.last_insert_rowid(), &pool).await?;

    Ok(insert.rows_affected())
}

async fn insert_targets(scope: &FlowScope, scope_id: i64, pool: &DbConnection) -> Result<u64> {
    let mut affected = 0;
    if let Some(targets) = &scope.targets {
        for device_mac in targets {
            match device_service::find_by_mac_or_duid(Some(device_mac.clone()), None, &pool).await {
                Err(e) => warn!("Device in FlowScope not found by MAC address {}: {:?}", device_mac, e),
                Ok(device) => {
                    let insert = sqlx::query!(
                        "INSERT INTO flow_scopes_devices (flow_scope_id, device_id) values ($1, $2)",
                        scope_id,
                        device.id,
                    )
                    .execute(pool)
                    .await?;
                    affected += insert.rows_affected();
                },
            }
        }
    }
    Ok(affected)
}

// ///returns room by id from the database
// pub async fn find_by_id(id: i64, pool: &DbConnection) -> Result<Room> {
//     let room = sqlx::query_as!(Room, "SELECT * FROM rooms WHERE room_id = $1", id)
//         .fetch_one(pool)
//         .await?;

//     Ok(room)
// }

// ///returns room by name from the database
// pub async fn find_by_name(name: &str, pool: &DbConnection) -> Result<Room> {
//     let room = sqlx::query_as!(Room, "SELECT * FROM rooms WHERE name = $1", name)
//         .fetch_one(pool)
//         .await?;

//     Ok(room)
// }

// ///updates a room with a new name and color in the database
// pub async fn update(room: &Room, pool: &DbConnection) -> Result<bool> {
//     let upd_count = sqlx::query!(
//         "UPDATE rooms SET name = $1, color = $2 WHERE room_id = $3",
//         room.name,
//         room.color,
//         room.room_id
//     )
//     .execute(pool)
//     .await?;

//     Ok(upd_count.rows_affected() == 1)
// }

// ///returns all devices that are associated with a given room from the database
// pub async fn get_all_devices_inside_room(room_id: i64, pool: &DbConnection) -> Result<Vec<Device>> {
//     let device_dbo: Vec<DeviceDbo> = sqlx::query_as!(DeviceDbo, "SELECT * FROM devices WHERE room_id = $1", room_id)
//         .fetch_all(pool)
//         .await?;

//     Ok(device_dbo.into_iter().map(Device::from).collect())
// }

// ///Creates a new room with a given name and color in the database
// pub async fn insert_room(room: &Room, pool: &DbConnection) -> Result<u64> {
//     let insert = sqlx::query!("INSERT INTO rooms (name, color) VALUES ($1, $2)", room.name, room.color)
//         .execute(pool)
//         .await?;

//     Ok(insert.rows_affected())
// }

// ///Deletes a room with a given name from database
// pub async fn delete_room(name: &str, pool: &DbConnection) -> Result<u64> {
//     let del_count = sqlx::query!("DELETE FROM rooms WHERE name = $1", name)
//         .execute(pool)
//         .await?;

//     Ok(del_count.rows_affected())
// }
