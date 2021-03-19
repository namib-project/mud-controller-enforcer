use crate::{
    db::DbConnection,
    error::{Error, Result},
    models::{Device, DeviceDbo},
    services::{
        config_service, config_service::ConfigKeys, firewall_configuration_service, mud_service,
        mud_service::get_mud_from_url,
    },
};
pub use futures::TryStreamExt;

use namib_shared::models::DhcpLeaseInformation;
use sqlx::Done;
use crate::models::Room;


pub async fn find_by_id(id: i64, pool: &DbConnection) -> Result<Room> {
    let room = sqlx::query_as!(Room, "select * from rooms where room_id = ?", id)
        .fetch_one(pool)
        .await?;

    Ok(room)
}

pub async fn find_by_name(name: String, pool: &DbConnection) -> Result<Room> {
    let room = sqlx::query_as!(Room, "select * from rooms where name = ?", name)
        .fetch_one(pool)
        .await?;

    Ok(room)
}

/*pub fn find_by_optional_id(id: Option<i64>, pool: &DbConnection) -> Result<Option<Room>> {
    match id {
        Some(room) => Ok(Some(find_by_id(room, pool))),
        None => Ok(None)
    }
}*/

pub fn convert_devicedbo_and_room_to_device(device: DeviceDbo, room: Room) -> Device {
    let mut device_with_room = Device::from(device);
    device_with_room.room = Some(room);
    device_with_room
}

pub async fn update(id: i64, room: &Room, conn: &DbConnection) -> Result<u64> {
    let upd_count = sqlx::query!(
        "update rooms set name = ?, color = ? where room_id = ?",
        room.name,
        room.color,
        id
    )
        .execute(conn)
        .await?;

    Ok(upd_count.rows_affected())
}

pub async fn get_all_rooms(pool: &DbConnection) -> Result<Vec<Room>> {
    let room_data = sqlx::query_as!(Room, "select * from rooms").fetch_all(pool).await?;

    Ok(room_data)
}

pub async fn get_all_devices_in_room(id: i64, pool: &DbConnection) -> Result<Vec<Device>> {
    let devices = sqlx::query_as!(DeviceDbo, "select * from devices where room_id = ?", id).fetch(pool);

    let devices_data = devices
            .err_into::<Error>()
            .and_then(|device| async {
                let mut device_data = Device::from(device);
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

pub async fn delete_room(id: i64, pool: &DbConnection) -> Result<u64> {
    let del_count = sqlx::query!("delete from rooms where room_id = ?", id)
        .execute(pool)
        .await?;

    Ok(del_count.rows_affected())
}
