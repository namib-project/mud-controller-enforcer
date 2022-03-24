// Copyright 2020-2022, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach, Matthias Reichmann
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::net::{Ipv4Addr, Ipv6Addr};

use namib_shared::{macaddr::SerdeMacAddr, models::DhcpLeaseInformation};

use std::string::ToString;

use crate::{
    db::DbConnection,
    error::Result,
    models::{Device, DeviceDbo, DeviceWithRefs},
    services::{config_service, config_service::ConfigKeys, firewall_configuration_service, neo4things_service},
};

pub async fn upsert_device_from_dhcp_lease(lease_info: DhcpLeaseInformation, pool: &DbConnection) -> Result<()> {
    debug!("dhcp request device mud file: {:?}", lease_info.mud_url);

    if let Ok(mut device) =
        find_by_mac_or_duid(lease_info.mac_address, lease_info.duid().map(ToString::to_string), pool).await
    {
        device.apply(lease_info);

        remove_existing_ips(device.ipv4_addr, device.ipv6_addr, pool).await?;

        update_device(&device.load_refs(pool).await?, pool).await?;
    } else {
        let collect_info = lease_info.mud_url.is_none()
            && config_service::get_config_value(ConfigKeys::CollectDeviceData.as_ref(), pool)
                .await
                .unwrap_or(false);

        let device = Device::new(lease_info, collect_info);

        remove_existing_ips(device.ipv4_addr, device.ipv6_addr, pool).await?;

        insert_device(&device.load_refs(pool).await?, pool).await?;
    }

    Ok(())
}

async fn remove_existing_ips(ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>, pool: &DbConnection) -> Result<()> {
    if let Some(ipv4) = ipv4 {
        let ipv4_string = ipv4.to_string();
        sqlx::query!("UPDATE devices SET ipv4_addr = NULL WHERE ipv4_addr = $1", ipv4_string)
            .execute(pool)
            .await?;
    }
    if let Some(ipv6) = ipv6 {
        let ipv6_string = ipv6.to_string();
        sqlx::query!("UPDATE devices SET ipv6_addr = NULL WHERE ipv6_addr = $1", ipv6_string)
            .execute(pool)
            .await?;
    }
    Ok(())
}

pub async fn get_all_devices(pool: &DbConnection) -> Result<Vec<Device>> {
    let devices = sqlx::query_as!(DeviceDbo, "SELECT * FROM devices")
        .fetch_all(pool)
        .await?;

    Ok(devices.into_iter().map(Device::from).collect())
}

pub async fn get_all_quarantined_devices(pool: &DbConnection) -> Result<Vec<Device>> {
    let devices = sqlx::query_as!(DeviceDbo, "SELECT * FROM devices WHERE q_bit = true")
        .fetch_all(pool)
        .await?;

    Ok(devices.into_iter().map(Device::from).collect())
}

pub async fn get_unidentified_devices(pool: &DbConnection) -> Result<Vec<Device>> {
    // TODO: Define when a device is unidentified
    let devices = sqlx::query_as!(DeviceDbo, "SELECT * FROM devices WHERE mud_url IS NULL")
        .fetch_all(pool)
        .await?;

    Ok(devices.into_iter().map(Device::from).collect())
}

pub async fn find_by_id(id: i64, pool: &DbConnection) -> Result<Device> {
    let device: DeviceDbo = sqlx::query_as!(DeviceDbo, "SELECT * FROM devices WHERE id = $1", id)
        .fetch_one(pool)
        .await?;

    Ok(Device::from(device))
}

pub async fn find_by_ip(ip: &str, pool: &DbConnection) -> Result<Device> {
    let device = sqlx::query_as!(
        DeviceDbo,
        "SELECT * FROM devices WHERE ipv4_addr = $1 OR ipv6_addr = $2",
        ip,
        ip
    )
    .fetch_optional(pool)
    .await?;

    if let Some(device) = device {
        Ok(Device::from(device))
    } else {
        Err(sqlx::error::Error::RowNotFound.into())
    }
}

pub async fn find_by_mac_or_duid(
    mac_addr: Option<SerdeMacAddr>,
    duid: Option<String>,
    pool: &DbConnection,
) -> Result<Device> {
    let mut device = None;
    if let Some(mac_addr) = mac_addr {
        let mac_addr_string = mac_addr.to_string();
        device = sqlx::query_as!(DeviceDbo, "SELECT * FROM devices WHERE mac_addr = $1", mac_addr_string)
            .fetch_optional(pool)
            .await?;
    }
    if device.is_none() && duid.is_some() {
        device = sqlx::query_as!(DeviceDbo, "SELECT * FROM devices WHERE duid = $1", duid)
            .fetch_optional(pool)
            .await?;
    }
    if let Some(device) = device {
        Ok(Device::from(device))
    } else {
        Err(sqlx::error::Error::RowNotFound.into())
    }
}

pub async fn insert_device(device_data: &DeviceWithRefs, pool: &DbConnection) -> Result<i64> {
    let ipv4_addr = device_data.ipv4_addr.map(|ip| ip.to_string());
    let ipv6_addr = device_data.ipv6_addr.map(|ip| ip.to_string());
    let mac_addr = device_data.mac_addr.map(|m| m.to_string());

    #[cfg(not(feature = "postgres"))]
    let result = sqlx::query!(
        "INSERT INTO devices (name, ipv4_addr, ipv6_addr, mac_addr, duid, hostname, vendor_class, mud_url, collect_info, last_interaction, room_id, fa_icon) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        device_data.name,
        ipv4_addr,
        ipv6_addr,
        mac_addr,
        device_data.duid,
        device_data.hostname,
        device_data.vendor_class,
        device_data.mud_url,
        device_data.collect_info,
        device_data.last_interaction,
        device_data.room_id,
        device_data.fa_icon,
    )
    .execute(pool)
    .await?
    .last_insert_rowid();

    #[cfg(feature = "postgres")]
    let result = sqlx::query!(
        "INSERT INTO devices (name, ipv4_addr, ipv6_addr, mac_addr, duid, hostname, vendor_class, mud_url, collect_info, last_interaction, room_id, fa_icon, q_bit) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING id",
        device_data.name,
        ipv4_addr,
        ipv6_addr,
        mac_addr,
        device_data.duid,
        device_data.hostname,
        device_data.vendor_class,
        device_data.mud_url,
        device_data.collect_info,
        device_data.last_interaction,
        device_data.room_id,
        device_data.fa_icon,
        device_data.q_bit,
    )
    .fetch_one(pool)
    .await?
    .id;

    if device_data.collect_info {
        // add the device in the background as it may take some time
        tokio::spawn(neo4things_service::add_device(result, device_data.inner.clone()));
    }

    firewall_configuration_service::update_config_version(pool).await?;

    Ok(result)
}

pub async fn update_device(device_data: &DeviceWithRefs, pool: &DbConnection) -> Result<bool> {
    let ipv4_addr = device_data.ipv4_addr.map(|ip| ip.to_string());
    let ipv6_addr = device_data.ipv6_addr.map(|ip| ip.to_string());
    let mac_addr = device_data.mac_addr.map(|m| m.to_string());

    let upd_count = sqlx::query!(
        "UPDATE devices SET name = $1, ipv4_addr = $2, ipv6_addr = $3, mac_addr = $4, duid = $5, hostname = $6, vendor_class = $7, mud_url = $8, collect_info = $9, last_interaction = $10, room_id = $11, fa_icon = $12, q_bit = $13 WHERE id = $14",
        device_data.name,
        ipv4_addr,
        ipv6_addr,
        mac_addr,
        device_data.duid,
        device_data.hostname,
        device_data.vendor_class,
        device_data.mud_url,
        device_data.collect_info,
        device_data.last_interaction,
        device_data.room_id,
        device_data.fa_icon,
        device_data.q_bit,
        device_data.id
    )
    .execute(pool)
    .await?;

    firewall_configuration_service::update_config_version(pool).await?;

    Ok(upd_count.rows_affected() == 1)
}

pub async fn delete_device(id: i64, pool: &DbConnection) -> Result<bool> {
    let del_count = sqlx::query!("DELETE FROM devices WHERE id = $1", id)
        .execute(pool)
        .await?;

    firewall_configuration_service::update_config_version(pool).await?;

    Ok(del_count.rows_affected() == 1)
}

/// Sets the quarantine status of the device with the given ID.
/// Returns whether the device's quarantine status was changed by this.
pub async fn change_quarantine_status_device(id: i64, pool: &DbConnection, status: bool) -> Result<bool> {
    let upd_count = sqlx::query!("UPDATE devices SET q_bit = $1 WHERE id = $2", status, id)
        .execute(pool)
        .await?;

    firewall_configuration_service::update_config_version(pool).await?;

    Ok(upd_count.rows_affected() == 1)
}
