// Copyright 2022, Jasper Wiegratz, Hannes Masuch
// SPDX-License-Identifier: MIT OR Apache-2.0

use chrono::{Duration, NaiveDateTime, Utc};
use namib_controller::db::DbConnection;
use namib_controller::error::Result;
use namib_controller::models::{Device, EndsAt, FlowScope, FlowScopeLevel};
use namib_controller::services::{device_service, flow_scope_service};
use namib_shared::macaddr::{MacAddr6, SerdeMacAddr};
use std::thread::sleep;
use std::time;

mod lib;

/// Insert devices without handlers to these devices modifying the flow scope state
async fn insert_device_without_scopes(device: &Device, pool: &DbConnection) -> Result<()> {
    let previous_scopes = flow_scope_service::get_all_flow_scopes(pool)
        .await?
        .into_iter()
        .map(|f| f.id)
        .collect::<Vec<_>>();

    device_service::insert_device(device, pool).await?;

    for scope in &flow_scope_service::get_all_flow_scopes(pool).await? {
        if !previous_scopes.contains(&scope.id) {
            flow_scope_service::remove_flow_scope(scope.id, pool).await?;
        }
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_flow_scopes() -> Result<()> {
    let ctx = lib::IntegrationTestContext::new("test_get_flow_scopes").await;

    let device_mac = SerdeMacAddr::V6(MacAddr6::new(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB));
    let device = Device {
        id: 1,
        name: Some(String::from("test_device")),
        ipv4_addr: None,
        ipv6_addr: None,
        mac_addr: Some(device_mac),
        duid: None,
        hostname: String::from("test_device"),
        vendor_class: String::from(""),
        mud_url: None,
        collect_info: false,
        last_interaction: NaiveDateTime::from_timestamp(42_000_000, 0),
        room_id: None,
        fa_icon: None,
        q_bit: false,
        log_anomalies: true,
    };

    insert_device_without_scopes(&device, &ctx.db_conn).await?;

    let scope_data = [
        (
            "fullscope",
            FlowScopeLevel::Full,
            3600,
            NaiveDateTime::from_timestamp(42_000_000, 0),
        ),
        (
            "headers",
            FlowScopeLevel::HeadersOnly,
            1800,
            NaiveDateTime::from_timestamp(42_000_000, 0),
        ),
        (
            "active_and_full",
            FlowScopeLevel::Full,
            7200,
            Utc::now().naive_utc().checked_sub_signed(Duration::seconds(1)).unwrap(),
        ),
    ];

    for scope_values in &scope_data {
        let device_macs = vec![
            device_mac,
            SerdeMacAddr::V6(MacAddr6::new(0x11, 0x22, 0x44, 0x66, 0x88, 0xAA)),
        ];
        flow_scope_service::insert_flow_scope(
            device_macs,
            &FlowScope {
                name: String::from(scope_values.0),
                level: scope_values.1.clone(),
                ttl: scope_values.2,
                starts_at: scope_values.3,
            },
            &ctx.db_conn,
        )
        .await?;
    }

    assert_eq!(flow_scope_service::get_active_flow_scopes(&ctx.db_conn).await?.len(), 1);
    assert_eq!(flow_scope_service::get_all_flow_scopes(&ctx.db_conn).await?.len(), 3);

    let id_empty = flow_scope_service::insert_flow_scope(
        vec![],
        &FlowScope {
            name: "active_and_empty".to_string(),
            level: FlowScopeLevel::Full,
            ttl: 7200,
            starts_at: Utc::now().naive_utc().checked_sub_signed(Duration::seconds(1)).unwrap(),
        },
        &ctx.db_conn,
    )
    .await?;

    assert_eq!(
        flow_scope_service::get_active_flow_scopes_for_device(&ctx.db_conn, 1)
            .await?
            .len(),
        1
    );
    assert_eq!(flow_scope_service::get_active_flow_scopes(&ctx.db_conn).await?.len(), 2);
    let scopes: Vec<FlowScope> = flow_scope_service::get_all_flow_scopes(&ctx.db_conn)
        .await?
        .into_iter()
        .map(|f| FlowScope::from(f))
        .collect();
    assert_eq!(scopes.len(), 4);

    scopes
        .iter()
        .zip(scope_data.iter())
        .map(|(dbo, data)| {
            println!("Scope: {} {:?} {}", dbo.name, dbo.level, dbo.ttl);
            assert_eq!(dbo.name, data.0);
            assert_eq!(dbo.level, data.1);
            assert_eq!(dbo.ttl, data.2);
            println!("Scope: {} {:?} {}", data.0, data.1, data.2);
        })
        .count();

    flow_scope_service::remove_flow_scope(id_empty, &ctx.db_conn).await?;
    assert_eq!(flow_scope_service::get_all_flow_scopes(&ctx.db_conn).await?.len(), 3);

    assert_eq!(
        flow_scope_service::remove_targets_from_scope(
            vec![device_mac],
            flow_scope_service::find_id_by_name(&ctx.db_conn, "active_and_full").await?,
            &ctx.db_conn
        )
        .await?,
        1
    );
    assert_eq!(
        flow_scope_service::get_active_flow_scopes_for_device(&ctx.db_conn, 1)
            .await?
            .len(),
        0
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_unlimited_flow_scope() -> Result<()> {
    let ctx = lib::IntegrationTestContext::new("test_unlimited_flow_scope").await;

    flow_scope_service::insert_flow_scope(
        Vec::new(),
        &FlowScope {
            name: String::from("test_scope"),
            level: FlowScopeLevel::Full,
            ttl: 0,
            starts_at: NaiveDateTime::from_timestamp(42_000_000, 0),
        },
        &ctx.db_conn,
    )
    .await?;

    let fs = flow_scope_service::get_active_flow_scopes(&ctx.db_conn).await?;

    for fs in fs {
        assert_eq!(fs.ends_at(), fs.starts_at);
    }

    assert_eq!(flow_scope_service::get_active_flow_scopes(&ctx.db_conn).await?.len(), 1);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_flow_scope_by_name() -> Result<()> {
    let ctx = lib::IntegrationTestContext::new("test_get_flow_scope_by_name").await;

    flow_scope_service::insert_flow_scope(
        Vec::new(),
        &FlowScope {
            name: String::from("test_scope"),
            level: FlowScopeLevel::Full,
            ttl: 3600,
            starts_at: NaiveDateTime::from_timestamp(42_000_000, 0),
        },
        &ctx.db_conn,
    )
    .await?;

    let scope_by_name = flow_scope_service::find_by_name(&ctx.db_conn, &String::from("test_scope")).await?;
    assert_eq!(scope_by_name.ttl, 3600);
    assert_eq!(scope_by_name.name, String::from("test_scope"));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_flow_scope_ttl_validation() -> Result<()> {
    let ctx = lib::IntegrationTestContext::new("test_flow_scope_ttl_validation").await;

    let device_mac = SerdeMacAddr::V6(MacAddr6::new(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB));
    let device = Device {
        id: 1,
        name: Some(String::from("test_device")),
        ipv4_addr: None,
        ipv6_addr: None,
        mac_addr: Some(device_mac),
        duid: None,
        hostname: String::from("test_device"),
        vendor_class: String::from(""),
        mud_url: None,
        collect_info: false,
        last_interaction: NaiveDateTime::from_timestamp(42_000_000, 0),
        room_id: None,
        fa_icon: None,
        q_bit: false,
        log_anomalies: true,
    };

    insert_device_without_scopes(&device, &ctx.db_conn).await?;

    assert_eq!(flow_scope_service::get_active_flow_scopes(&ctx.db_conn).await?.len(), 0);

    flow_scope_service::insert_flow_scope(
        vec![device.mac_addr.unwrap()],
        &FlowScope {
            name: String::from("test_scope"),
            level: FlowScopeLevel::Full,
            ttl: 5,
            starts_at: Utc::now().naive_local(),
        },
        &ctx.db_conn,
    )
    .await?;
    assert_eq!(flow_scope_service::get_active_flow_scopes(&ctx.db_conn).await?.len(), 1);

    sleep(time::Duration::from_secs(5));
    assert_eq!(flow_scope_service::get_active_flow_scopes(&ctx.db_conn).await?.len(), 0);

    Ok(())
}
