use crate::{
    db::DbConnection,
    error::{Error, Result},
    models::{Device, DeviceDbo},
    services::{
        config_service, config_service::ConfigKeys, firewall_configuration_service, mud_service,
        mud_service::get_or_fetch_mud, neo4jthings_service,
    },
};
pub use futures::TryStreamExt;

use namib_shared::{models::DhcpLeaseInformation, MacAddr};

pub async fn upsert_device_from_dhcp_lease(lease_info: DhcpLeaseInformation, pool: &DbConnection) -> Result<()> {
    let (device, update) = if let Ok(mut device) = find_by_mac_or_duid(
        lease_info.mac_address,
        lease_info.duid().map(|d| d.to_string()),
        false,
        pool,
    )
    .await
    {
        device.apply(lease_info);
        (device, true)
    } else {
        let mut device = Device::new(lease_info);
        device.collect_info = device.mud_url.is_none()
            && config_service::get_config_value(ConfigKeys::CollectDeviceData.as_ref(), pool)
                .await
                .unwrap_or(false);
        (device, false)
    };

    debug!("dhcp request device mud file: {:?}", device.mud_url);

    match &device.mud_url {
        Some(url) => mud_service::get_or_fetch_mud(&url, pool).await.ok(),
        None => None,
    };
    if update {
        update_device(&device, pool).await.unwrap();
    } else {
        insert_device(&device, pool).await.unwrap();
    }

    firewall_configuration_service::update_config_version(pool).await?;

    Ok(())
}

pub async fn get_all_devices(pool: &DbConnection) -> Result<Vec<Device>> {
    let devices = sqlx::query_as!(DeviceDbo, "select * from devices").fetch(pool);

    let devices_data = devices
        .err_into::<Error>()
        .and_then(|device| async {
            let mut device_data = Device::from(device);
            device_data.mud_data = match device_data.mud_url.clone() {
                Some(url) => {
                    let data = get_or_fetch_mud(&url, pool).await;
                    debug!("Get all devices: mud url {:?}: {:?}", url, data);
                    data.ok()
                },
                None => None,
            };

            Ok(device_data)
        })
        .try_collect::<Vec<Device>>()
        .await?;

    Ok(devices_data)
}

pub async fn find_by_id(id: i64, fetch_mud: bool, pool: &DbConnection) -> Result<Device> {
    let device = sqlx::query_as!(DeviceDbo, "select * from devices where id = ?", id)
        .fetch_one(pool)
        .await?;

    let device = Device::from(device);

    if fetch_mud && device.mud_url.is_some() {
        device.mud_data = Some(mud_service::get_or_fetch_mud(device.mud_url.as_ref().unwrap(), pool).await?);
    }

    Ok(device)
}

pub async fn find_by_ip(ip: &str, fetch_mud: bool, pool: &DbConnection) -> Result<Device> {
    let device = sqlx::query_as!(
        DeviceDbo,
        "select * from devices where ipv4_addr = ? or ipv6_addr = ?",
        ip,
        ip
    )
    .fetch_one(pool)
    .await?;

    let mut device = Device::from(device);

    if fetch_mud && device.mud_url.is_some() {
        device.mud_data = Some(mud_service::get_or_fetch_mud(device.mud_url.as_ref().unwrap(), pool).await?);
    }

    Ok(device.into())
}

pub async fn find_by_mac_or_duid(
    mac_addr: Option<MacAddr>,
    duid: Option<String>,
    fetch_mud: bool,
    pool: &DbConnection,
) -> Result<Device> {
    if let Some(mac_addr) = mac_addr {
        let mac_addr_string = mac_addr.to_string();
        let device = sqlx::query_as!(DeviceDbo, "select * from devices where mac_addr = ?", mac_addr_string)
            .fetch_optional(pool)
            .await?;
        if let Some(device) = device {
            return Ok(device.into());
        }
    }
    if let Some(duid) = duid {
        let device = sqlx::query_as!(DeviceDbo, "select * from devices where duid = ?", duid)
            .fetch_one(pool)
            .await?;
        Ok(device.into())
    } else {
        Err(sqlx::error::Error::RowNotFound.into())
    }
}

pub async fn insert_device(device_data: &Device, pool: &DbConnection) -> Result<i64> {
    let ipv4_addr = device_data.ipv4_addr.map(|ip| ip.to_string());
    let ipv6_addr = device_data.ipv6_addr.map(|ip| ip.to_string());
    let mac_addr = device_data.mac_addr.map(|m| m.to_string());
    let ins_count = sqlx::query!(
        "insert into devices (name, ipv4_addr, ipv6_addr, mac_addr, duid, hostname, vendor_class, mud_url, collect_info, last_interaction, clipart) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        device_data.clipart,
    )
    .execute(pool)
    .await?;

    if device_data.collect_info {
        // add the device in the background as it may take some time
        tokio::spawn(neo4jthings_service::add_device(device_data.clone()));
    }

    Ok(ins_count.last_insert_rowid())
}

pub async fn update_device(device_data: &Device, pool: &DbConnection) -> Result<bool> {
    let ipv4_addr = device_data.ipv4_addr.map(|ip| ip.to_string());
    let ipv6_addr = device_data.ipv6_addr.map(|ip| ip.to_string());
    let mac_addr = device_data.mac_addr.map(|m| m.to_string());
    let upd_count = sqlx::query!(
        "update devices set name = ?, ipv4_addr = ?, ipv6_addr = ?, mac_addr = ?, duid = ?, hostname = ?, vendor_class = ?, mud_url = ?, collect_info = ?, last_interaction = ?, clipart = ? where id = ?",
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
