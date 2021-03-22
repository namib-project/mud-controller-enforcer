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

use namib_shared::models::DhcpLeaseInformation;
use sqlx::Done;

pub async fn upsert_device_from_dhcp_lease(lease_info: DhcpLeaseInformation, pool: &DbConnection) -> Result<()> {
    let mut dhcp_device_data = Device::from(lease_info);
    let update = if let Ok(device) = find_by_ip(dhcp_device_data.ip_addr, pool).await {
        dhcp_device_data.id = device.id;
        dhcp_device_data.collect_info = device.collect_info;
        true
    } else {
        dhcp_device_data.collect_info = dhcp_device_data.mud_url.is_none()
            && config_service::get_config_value(ConfigKeys::CollectDeviceData.as_ref(), pool)
                .await
                .unwrap_or(false);
        false
    };

    debug!("dhcp request device mud file: {:?}", dhcp_device_data.mud_url);

    match &dhcp_device_data.mud_url {
        Some(url) => mud_service::get_or_fetch_mud(url.clone(), pool).await.ok(),
        None => None,
    };
    if update {
        update_device(&dhcp_device_data, pool).await.unwrap();
    } else {
        insert_device(&dhcp_device_data, pool).await.unwrap();
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
                    let data = get_or_fetch_mud(url.clone(), pool).await;
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

pub async fn find_by_id(id: i64, pool: &DbConnection) -> Result<Device> {
    let device = sqlx::query_as!(DeviceDbo, "select * from devices where id = ?", id)
        .fetch_one(pool)
        .await?;

    Ok(Device::from(device))
}

pub async fn find_by_ip(ip_addr: std::net::IpAddr, pool: &DbConnection) -> Result<Device> {
    let ip_addr = ip_addr.to_string();
    let device = sqlx::query_as!(DeviceDbo, "select * from devices where ip_addr = ?", ip_addr)
        .fetch_one(pool)
        .await?;

    Ok(Device::from(device))
}

pub async fn insert_device(device_data: &Device, pool: &DbConnection) -> Result<u64> {
    let ip_addr = device_data.ip_addr.to_string();
    let mac_addr = device_data.mac_addr.map(|m| m.to_string());
    let ins_count = sqlx::query!(
        "insert into devices (ip_addr, mac_addr, hostname, vendor_class, mud_url, collect_info, last_interaction, clipart) values (?, ?, ?, ?, ?, ?, ?, ?)",
        ip_addr,
        mac_addr,
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

    Ok(ins_count.rows_affected())
}

pub async fn update_device(device_data: &Device, pool: &DbConnection) -> Result<bool> {
    let ip_addr = device_data.ip_addr.to_string();
    let mac_addr = device_data.mac_addr.map(|m| m.to_string());
    let upd_count = sqlx::query!(
        "update devices set ip_addr = ?, mac_addr = ?, hostname = ?, vendor_class = ?, mud_url = ?, collect_info = ?, last_interaction = ?, clipart = ? where id = ?",
        ip_addr,
        mac_addr,
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
