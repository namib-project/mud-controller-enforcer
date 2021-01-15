use crate::{
    db::ConnectionType,
    error::{Error, Result},
    models::device_model::{Device, DeviceDbo},
    services::mud_service::get_mud_from_url,
};
use futures::TryStreamExt;
use namib_shared::mac;
use sqlx::Done;

pub async fn get_all_devices(pool: &ConnectionType) -> Result<Vec<Device>> {
    let devices = sqlx::query_as!(DeviceDbo, "select * from devices").fetch(pool);

    let devices_data = devices
        .err_into::<Error>()
        .and_then(|device| async {
            let mut device_data = Device {
                id: device.id,
                ip_addr: device.ip_addr.parse()?,
                mac_addr: device
                    .mac_addr
                    .and_then(|mac| mac.parse::<mac::MacAddr>().ok())
                    .map(|mac| mac.into()),
                hostname: device.hostname,
                vendor_class: device.vendor_class,
                mud_url: device.mud_url,
                last_interaction: device.last_interaction,
                mud_data: None,
            };
            device_data.mud_data = match device_data.mud_url.clone() {
                Some(url) => {
                    let data = get_mud_from_url(url.clone(), pool).await;
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

pub async fn find_by_id(id: i32, pool: &ConnectionType) -> Result<Device> {
    let device = sqlx::query_as!(DeviceDbo, "select * from devices where id = ?", id)
        .fetch_one(pool)
        .await?;

    Ok(Device::from(device))
}

pub async fn find_by_ip(ip_addr: std::net::IpAddr, pool: &ConnectionType) -> Result<Device> {
    let ip_addr = ip_addr.to_string();
    let device = sqlx::query_as!(DeviceDbo, "select * from devices where ip_addr = ?", ip_addr)
        .fetch_one(pool)
        .await?;

    Ok(Device::from(device))
}

pub async fn insert_device(device_data: &Device, pool: &ConnectionType) -> Result<u64> {
    let ip_addr = device_data.ip_addr.to_string();
    let mac_addr = device_data.mac_addr.map(|m| m.to_string());
    let ins_count = sqlx::query!(
        "insert into devices (ip_addr, mac_addr, hostname, vendor_class, mud_url, last_interaction) values (?, ?, ?, ?, ?, ?)",
        ip_addr,
        mac_addr,
        device_data.hostname,
        device_data.vendor_class,
        device_data.mud_url,
        device_data.last_interaction,
    )
    .execute(pool)
    .await?;

    Ok(ins_count.rows_affected())
}

pub async fn update_device(device_data: &Device, pool: &ConnectionType) -> Result<u64> {
    let ip_addr = device_data.ip_addr.to_string();
    let mac_addr = device_data.mac_addr.map(|m| m.to_string());
    let upd_count = sqlx::query!(
        "update devices set ip_addr = ?, mac_addr = ?, hostname = ?, vendor_class = ?, mud_url = ?, last_interaction = ? where id = ?",
        ip_addr,
        mac_addr,
        device_data.hostname,
        device_data.vendor_class,
        device_data.mud_url,
        device_data.last_interaction,
        device_data.id,
    )
    .execute(pool)
    .await?;

    Ok(upd_count.rows_affected())
}

pub async fn delete_device(id: i32, pool: &ConnectionType) -> Result<u64> {
    let del_count = sqlx::query!("delete from devices where id = ?", id)
        .execute(pool)
        .await?;

    Ok(del_count.rows_affected())
}
