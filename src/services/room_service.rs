use crate::{
    db::DbConnection,
    error::{Error, Result},
    models::{Device, Room},
    services::device_service::get_all_devices,
};
pub use futures::TryStreamExt;

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
}

pub async fn get_room_by_name(name: String, pool: &DbConnection) -> Result<Option<Room>> {
    let room = sqlx::query_as!(Room, "SELECT room_id, name, color FROM rooms WHERE name= ?", name)
        .fetch_one(pool)
        .await?;

    Ok(Some(room))
}

pub async fn get_all_devices_inside_room(room_id: i64, pool: &DbConnection) -> Result<Vec<Device>> {
    let devices = get_all_devices(pool).await?;

    Ok(devices
        .into_iter()
        .filter(|d| d.room.is_some())
        .filter(|d| d.room.unwrap().room_id == room_id)
        .collect())
}

pub async fn insert_room(name: String, color: String) -> Result<i64> {
    Ok(1)
}
