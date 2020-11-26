use crate::{
    db::DbConnPool,
    error::Result,
    models::device_model::{Device, DeviceData, InsertableDevice},
    schema::devices,
    services::mud_service::get_mud_from_url,
};
use diesel::prelude::*;
use futures::{stream, StreamExt};
use std::net::IpAddr;

pub async fn get_all_devices(pool: DbConnPool) -> Result<Vec<DeviceData>> {
    let conn = pool.get_one().expect("couldn't get db conn from pool");
    let devices = devices::table.load::<Device>(&*conn)?;
    let devices_data = stream::iter(devices)
        .filter_map(|device| async {
            let mut device_data = DeviceData::from(device);
            device_data.mud_data = match device_data.mud_url.clone() {
                Some(url) => get_mud_from_url(url, pool.get_one().expect("couldn't get db conn from pool")).await.ok(),
                None => None,
            };
            Some(device_data)
        })
        .collect::<Vec<DeviceData>>()
        .await;

    Ok(devices_data)
}

pub async fn find_by_id(id: i32, pool: DbConnPool) -> Result<DeviceData> {
    let conn = pool.get_one().expect("couldn't get db conn from pool");
    let device = devices::table.find(id).get_result::<Device>(&*conn)?;

    Ok(DeviceData::from(device))
}

pub async fn find_by_ip(ip_addr: IpAddr, pool: DbConnPool) -> Result<DeviceData> {
    let conn = pool.get_one().expect("couldn't get db conn from pool");
    let device = devices::table.filter(devices::ip_addr.eq(ip_addr.to_string())).first::<Device>(&*conn)?;

    Ok(DeviceData::from(device))
}

pub async fn insert_device(device_data: &DeviceData, pool: DbConnPool) -> Result<usize> {
    let conn = pool.get_one().expect("couldn't get db conn from pool");
    let ins_count = diesel::insert_into(devices::table).values(InsertableDevice::from(device_data)).execute(&*conn)?;

    Ok(ins_count)
}

pub async fn update_device(device_data: &DeviceData, pool: DbConnPool) -> Result<usize> {
    let conn = pool.get_one().expect("couldn't get db conn from pool");
    let upd_count = diesel::update(devices::table.find(device_data.id)).set(Device::from(device_data)).execute(&*conn)?;

    Ok(upd_count)
}

pub async fn delete_device(id: i32, pool: DbConnPool) -> Result<usize> {
    let conn = pool.get_one().expect("couldn't get db conn from pool");
    let del_count = diesel::delete(devices::table.find(id)).execute(&*conn)?;

    Ok(del_count)
}
