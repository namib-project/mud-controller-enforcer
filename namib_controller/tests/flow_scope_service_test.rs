use chrono::{Duration, NaiveDateTime, Utc};
use namib_controller::error::Result;
use namib_controller::models::{Device, DeviceWithRefs};
use namib_controller::services::{device_service, flow_scope_service};
use namib_shared::flow_scope::{FlowScope, Level};
use namib_shared::macaddr::{MacAddr6, SerdeMacAddr};

mod lib;

#[tokio::test(flavor = "multi_thread")]
async fn test_get_flow_scopes() -> Result<()> {
    let ctx = lib::IntegrationTestContext::new("test_get_flow_scopes").await;

    let device_mac = SerdeMacAddr::V6(MacAddr6::new(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB));
    let device = DeviceWithRefs {
        controller_uris: vec![],
        inner: Device {
            id: 0,
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
            clipart: None,
            q_bit: false,
        },
        mud_data: None,
        room: None,
    };
    device_service::insert_device(&device, &ctx.db_conn).await?;

    let scope_data = [
        (
            "fullscope",
            Level::Full,
            3600,
            NaiveDateTime::from_timestamp(42_000_000, 0),
        ),
        (
            "headers",
            Level::HeadersOnly,
            1800,
            NaiveDateTime::from_timestamp(42_000_000, 0),
        ),
        (
            "active_and_full",
            Level::Full,
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
            &FlowScope {
                name: String::from(scope_values.0),
                targets: Some(device_macs),
                level: scope_values.1.clone(),
                ttl: scope_values.2,
                starts_at: scope_values.3,
            },
            &ctx.db_conn,
        )
        .await?;
    }

    assert_eq!(flow_scope_service::get_active_flow_scopes(&ctx.db_conn).await?.len(), 1);
    let scopes = flow_scope_service::get_all_flow_scopes(&ctx.db_conn).await?;
    assert_eq!(scopes.len(), 3);

    scopes
        .iter()
        .zip(scope_data.iter())
        .map(|(dbo, data)| {
            println!("Scope: {} {:?} {}", dbo.name, dbo.level, dbo.ttl);
            assert_eq!(dbo.name, data.0);
            //assert_eq!(dbo.level, data.1);
            assert_eq!(dbo.ttl, data.2);
            println!("Scope: {} {:?} {}", data.0, data.1, data.2);
        })
        .count();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_flow_scope_by_name() -> Result<()> {
    let ctx = lib::IntegrationTestContext::new("test_get_flow_scope_by_name").await;

    flow_scope_service::insert_flow_scope(
        &FlowScope {
            name: String::from("test_scope"),
            targets: Some(Vec::new()),
            level: Level::Full,
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
