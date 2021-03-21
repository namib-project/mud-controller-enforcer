use crate::{
    db::DbConnection,
    error::{Error, Result},
    models::{Device, DeviceDbo, Room},
    services::device_service::get_all_devices,
};
pub use futures::TryStreamExt;
use sqlx::Done;

pub async fn get_all_rooms(pool: &DbConnection) -> Result<Vec<Room>> {
    let room_data = sqlx::query_as!(Room, "select * from rooms").fetch_all(pool).await?;

    Ok(room_data)
}
/*
pub async fn get_all_rooms(pool: &DbConnection) -> Result<Vec<Room>> {
    let rooms: Vec<_> = sqlx::query!("SELECT room_id, name, color FROM rooms")
        .fetch_all(pool)
        .await?;

    Ok(rooms
        .into_iter()
        .map(|r| Room {
            room_id: r.room_id,
            name: r.name,
            color: r.color,
        })
        .collect())
}*/

pub async fn find_by_id(id: i64, pool: &DbConnection) -> Result<Room> {
    let room = sqlx::query_as!(Room, "select * from rooms where room_id = ?", id)
        .fetch_one(pool)
        .await?;

    Ok(room)
}

pub async fn find_by_name(name: String, pool: &DbConnection) -> Result<Option<Room>> {
    let room = sqlx::query_as!(Room, "SELECT room_id, name, color FROM rooms WHERE name= ?", name)
        .fetch_one(pool)
        .await?;

    Ok(Some(room))
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

pub async fn update(room: &Room, pool: &DbConnection) -> Result<u64> {
    let upd_count = sqlx::query!(
        "update rooms set name = ?, color = ? where room_id = ?",
        room.name,
        room.color,
        room.room_id
    )
    .execute(pool)
    .await?;

    Ok(upd_count.rows_affected())
}

pub async fn get_all_devices_inside_room(room_id: i64, pool: &DbConnection) -> Result<Vec<Device>> {
    let devices = get_all_devices(pool).await?;

    Ok(devices
        .into_iter()
        .filter(|d| d.room.is_some())
        .filter(|d| d.room.as_ref().unwrap().room_id == room_id)
        .collect())
}

pub async fn insert_room(name: String, color: String, pool: &DbConnection) -> Result<u64> {
    let insert = sqlx::query!("insert into rooms (name, color) values (?, ?)", name, color,)
        .execute(pool)
        .await?;

    Ok(insert.rows_affected())
}

pub async fn delete_room(name: String, pool: &DbConnection) -> Result<u64> {
    let del_count = sqlx::query!("delete from rooms where name = ?", name)
        .execute(pool)
        .await?;

    Ok(del_count.rows_affected())
}
