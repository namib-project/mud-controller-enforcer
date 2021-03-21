use crate::{
    db::DbConnection,
    error::Result,
    models::{Device, Room},
    services::device_service::get_all_devices,
};
pub use futures::TryStreamExt;
use sqlx::Done;

///returns all rooms from the database
pub async fn get_all_rooms(pool: &DbConnection) -> Result<Vec<Room>> {
    let room_data = sqlx::query_as!(Room, "select * from rooms").fetch_all(pool).await?;

    Ok(room_data)
}

///returns room by id from the database
pub async fn find_by_id(id: i64, pool: &DbConnection) -> Result<Room> {
    let room = sqlx::query_as!(Room, "select * from rooms where room_id = ?", id)
        .fetch_one(pool)
        .await?;

    Ok(room)
}

///returns room by name from the database
pub async fn find_by_name(name: String, pool: &DbConnection) -> Result<Room> {
    let room = sqlx::query_as!(Room, "SELECT room_id, name, color FROM rooms WHERE name= ?", name)
        .fetch_one(pool)
        .await?;

    Ok(room)
}

///updates a room with a new name and color in the database
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

///returns all devices that are associated with a given room from the database
pub async fn get_all_devices_inside_room(room_id: i64, pool: &DbConnection) -> Result<Vec<Device>> {
    let devices = get_all_devices(pool).await?;

    Ok(devices
        .into_iter()
        .filter(|d| d.room.is_some())
        .filter(|d| d.room.as_ref().unwrap().room_id == room_id)
        .collect())
}

///Creates a new room with a given name and color in the database
pub async fn insert_room(room: &Room, pool: &DbConnection) -> Result<u64> {
    let insert = sqlx::query!("insert into rooms (name, color) values (?, ?)", room.name, room.color,)
        .execute(pool)
        .await?;

    Ok(insert.rows_affected())
}

///Deletes a room with a given name from database
pub async fn delete_room(name: String, pool: &DbConnection) -> Result<u64> {
    let del_count = sqlx::query!("delete from rooms where name = ?", name)
        .execute(pool)
        .await?;

    Ok(del_count.rows_affected())
}
