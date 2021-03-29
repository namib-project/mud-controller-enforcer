use namib_shared::models::DhcpLeaseInformation;

use crate::{
    db::DbConnection,
    error::Result,
    models::{Device, DeviceDbo},
    services::{config_service, config_service::ConfigKeys, firewall_configuration_service, neo4jthings_service},
};

use crate::models::DeviceWithRefs;
use namib_shared::MacAddr;

pub async fn upsert_device_from_dhcp_lease(lease_info: DhcpLeaseInformation, pool: &DbConnection) -> Result<()> {
    debug!("dhcp request device mud file: {:?}", lease_info.mud_url);

    if let Ok(mut device) =
        find_by_mac_or_duid(lease_info.mac_address, lease_info.duid().map(|d| d.to_string()), pool).await
    {
        device.apply(lease_info);
        update_device(&device.load_refs(pool).await?, pool).await.unwrap();
    } else {
        let collect_info = lease_info.mud_url.is_none()
            && config_service::get_config_value(ConfigKeys::CollectDeviceData.as_ref(), pool)
                .await
                .unwrap_or(false);
        let device = Device::new(lease_info, collect_info);
        insert_device(&device.load_refs(pool).await?, pool).await.unwrap();
    }

    firewall_configuration_service::update_config_version(pool).await?;

    Ok(())
}

pub async fn get_all_devices(pool: &DbConnection) -> Result<Vec<Device>> {
    let devices = sqlx::query_as!(DeviceDbo, "select * from devices")
        .fetch_all(pool)
        .await?;

    Ok(devices.into_iter().map(Device::from).collect())
}

pub async fn find_by_id(id: i64, pool: &DbConnection) -> Result<Device> {
    let device: DeviceDbo = sqlx::query_as!(DeviceDbo, "select * from devices where id = ?", id)
        .fetch_one(pool)
        .await?;

    Ok(Device::from(device))
}

pub async fn find_by_ip(ip: &str, pool: &DbConnection) -> Result<Device> {
    let device = sqlx::query_as!(
        DeviceDbo,
        "select * from devices where ipv4_addr = ? or ipv6_addr = ?",
        ip,
        ip
    )
    .fetch_one(pool)
    .await?;

    Ok(Device::from(device))
}

pub async fn find_by_mac_or_duid(
    mac_addr: Option<MacAddr>,
    duid: Option<String>,
    pool: &DbConnection,
) -> Result<Device> {
    let mut device = None;
    if let Some(mac_addr) = mac_addr {
        let mac_addr_string = mac_addr.to_string();
        device = sqlx::query_as!(DeviceDbo, "select * from devices where mac_addr = ?", mac_addr_string)
            .fetch_optional(pool)
            .await?;
    }
    if device.is_none() && duid.is_some() {
        device = sqlx::query_as!(DeviceDbo, "select * from devices where duid = ?", duid)
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

    let ins_count = sqlx::query!(
        "insert into devices (name, ipv4_addr, ipv6_addr, mac_addr, duid, hostname, vendor_class, mud_url, collect_info, last_interaction, room_id, clipart) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        device_data.clipart,
    )
    .execute(pool)
    .await?;

    if device_data.collect_info {
        // add the device in the background as it may take some time
        tokio::spawn(neo4jthings_service::add_device(device_data.inner.clone()));
    }

    Ok(ins_count.last_insert_rowid())
}

pub async fn update_device(device_data: &DeviceWithRefs, pool: &DbConnection) -> Result<bool> {
    let ipv4_addr = device_data.ipv4_addr.map(|ip| ip.to_string());
    let ipv6_addr = device_data.ipv6_addr.map(|ip| ip.to_string());
    let mac_addr = device_data.mac_addr.map(|m| m.to_string());

    let upd_count = sqlx::query!(
        "update devices set name = ?, ipv4_addr = ?, ipv6_addr = ?, mac_addr = ?, duid = ?, hostname = ?, vendor_class = ?, mud_url = ?, collect_info = ?, last_interaction = ?, room_id = ?, clipart = ? where id = ?",
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
        device_data.clipart,
        device_data.id,
    )
    .execute(pool)
    .await?;

    Ok(upd_count.rows_affected() == 1)
}

pub async fn delete_device(id: i64, pool: &DbConnection) -> Result<bool> {
    let del_count = sqlx::query!("delete from devices where id = ?", id)
        .execute(pool)
        .await?;

    Ok(del_count.rows_affected() == 1)
}
