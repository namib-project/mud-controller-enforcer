// Copyright 2022, Jasper Wiegratz, Hannes Masuch
// SPDX-License-Identifier: MIT OR Apache-2.0

use chrono::{NaiveDateTime, Utc};
use namib_shared::macaddr::SerdeMacAddr;

use crate::{
    db::DbConnection,
    error::Result,
    models::{EndsAt, FlowScope, FlowScopeDbo},
    services::{device_service, firewall_configuration_service},
};

///returns all flow scopes from the database
pub async fn get_all_flow_scopes(pool: &DbConnection) -> Result<Vec<FlowScopeDbo>> {
    let flowscopes = sqlx::query_as!(FlowScopeDbo, "SELECT id, name, level, ttl, starts_at FROM flow_scopes")
        .fetch_all(pool)
        .await?;

    Ok(flowscopes)
}

///returns all currently active flow scopes from the database
pub async fn get_active_flow_scopes(pool: &DbConnection) -> Result<Vec<FlowScope>> {
    let flowscopes = get_all_flow_scopes(pool).await?;
    let active_flowscopes: Vec<FlowScope> = check_ttl(flowscopes);

    Ok(active_flowscopes)
}

///returns all active flow scopes for a device with `device_id`
pub async fn get_active_flow_scopes_for_device(pool: &DbConnection, device_id: i64) -> Result<Vec<FlowScope>> {
    let flowscopes = sqlx::query_as!(
        FlowScopeDbo,
        "SELECT f.* FROM flow_scopes f JOIN flow_scopes_devices as fd ON f.id = fd.flow_scope_id
           WHERE fd.device_id = $1",
        device_id
    )
    .fetch_all(pool)
    .await?;

    let active_flowscopes: Vec<FlowScope> = check_ttl(flowscopes);

    Ok(active_flowscopes)
}

///returns flow scope by name from the database
pub async fn find_by_name(pool: &DbConnection, name: &str) -> Result<FlowScope> {
    let flowscope = sqlx::query_as!(
        FlowScopeDbo,
        "SELECT id, name, level, ttl, starts_at FROM flow_scopes WHERE name = $1",
        name
    )
    .fetch_one(pool)
    .await?;
    Ok(FlowScope::from(flowscope))
}

///returns flow scope by name from the database
pub async fn find_id_by_name(pool: &DbConnection, name: &str) -> Result<i64> {
    Ok(sqlx::query!("SELECT id FROM flow_scopes WHERE name = $1", name)
        .fetch_one(pool)
        .await?
        .id)
}

///inserts flow scope into the database, returning the id
pub async fn insert_flow_scope(devices: Vec<SerdeMacAddr>, scope: &FlowScope, pool: &DbConnection) -> Result<i64> {
    let level = scope.level.clone() as i64;
    let flowscope_id = sqlx::query_as!(
        FlowScopeDbo,
        "INSERT INTO flow_scopes (name, level, ttl, starts_at) values ($1, $2, $3, $4) RETURNING *",
        scope.name,
        level,
        scope.ttl,
        scope.starts_at
    )
    .fetch_one(pool)
    .await?
    .id;

    if !devices.is_empty() {
        insert_targets(devices, flowscope_id, pool).await?;
    }

    Ok(flowscope_id)
}

pub async fn remove_flow_scope(scope_id: i64, pool: &DbConnection) -> Result<bool> {
    let result = sqlx::query!("DELETE FROM flow_scopes WHERE id = $1", scope_id)
        .execute(pool)
        .await?;

    firewall_configuration_service::update_config_version(pool).await?;
    Ok(result.rows_affected() == 1)
}

pub async fn insert_targets(targets: Vec<SerdeMacAddr>, scope_id: i64, pool: &DbConnection) -> Result<u64> {
    let mut affected = 0;
    for mac in targets {
        match device_service::find_by_mac_or_duid(Some(mac), None, pool).await {
            Err(e) => warn!("Device in FlowScope not found by MAC address {}: {:?}", mac, e),
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
    firewall_configuration_service::update_config_version(pool).await?;
    Ok(affected)
}

pub async fn remove_targets_from_scope(targets: Vec<SerdeMacAddr>, scope_id: i64, pool: &DbConnection) -> Result<u64> {
    let mut affected = 0;
    for mac in targets {
        match device_service::find_by_mac_or_duid(Some(mac), None, pool).await {
            Err(e) => warn!("Device in FlowScope not found by MAC address {}: {:?}", mac, e),
            Ok(device) => {
                let remove = sqlx::query!(
                    "DELETE FROM flow_scopes_devices WHERE device_id = $1 AND flow_scope_id = $2",
                    device.id,
                    scope_id
                )
                .execute(pool)
                .await?;

                affected += remove.rows_affected();
            },
        }
    }
    firewall_configuration_service::update_config_version(pool).await?;
    Ok(affected)
}

pub async fn get_next_expiration_date_time(pool: &DbConnection) -> Option<NaiveDateTime> {
    let active_flow_scopes = get_active_flow_scopes(pool).await.unwrap();

    if active_flow_scopes.is_empty() {
        None
    } else {
        let mut next_expiration_date_time = None;
        let now = Utc::now().naive_local();
        for flow_scope in active_flow_scopes {
            let flow_scope_end = flow_scope.ends_at();
            if next_expiration_date_time.is_none() {
                if flow_scope_end > now {
                    next_expiration_date_time = Some(flow_scope_end);
                }
            } else if flow_scope_end < next_expiration_date_time.unwrap() {
                next_expiration_date_time = Some(flow_scope_end);
            }
        }
        next_expiration_date_time
    }
}

fn check_ttl(flowscopes: Vec<FlowScopeDbo>) -> Vec<FlowScope> {
    let now = Utc::now().naive_local();
    flowscopes
        .into_iter()
        .filter(|fs| (fs.starts_at < now && now < fs.ends_at()))
        .map(FlowScope::from)
        .collect()
}
