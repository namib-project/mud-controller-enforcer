use crate::{
    db::DbConnection,
    error::Result,
    models::{Device, DeviceDbo, Room},
};

///returns all rooms from the database
pub async fn get_all_rooms(pool: &DbConnection) -> Result<Vec<Room>> {
    let room_data = sqlx::query_as!(Room, "SELECT * FROM rooms").fetch_all(pool).await?;

    Ok(room_data)
}

///returns room by id from the database
pub async fn find_by_id(id: i64, pool: &DbConnection) -> Result<Room> {
    let room = sqlx::query_as!(Room, "SELECT * FROM rooms WHERE room_id = $1", id)
        .fetch_one(pool)
        .await?;

    Ok(room)
}

///returns room by name from the database
pub async fn find_by_name(name: &str, pool: &DbConnection) -> Result<Room> {
    let room = sqlx::query_as!(Room, "SELECT * FROM rooms WHERE name = $1", name)
        .fetch_one(pool)
        .await?;

    Ok(room)
}

///updates a room with a new name and color in the database
pub async fn update(room: &Room, pool: &DbConnection) -> Result<bool> {
    let upd_count = sqlx::query!(
        "UPDATE rooms SET name = $1, color = $2 WHERE room_id = $3",
        room.name,
        room.color,
        room.room_id
    )
    .execute(pool)
    .await?;

    Ok(upd_count.rows_affected() == 1)
}

///returns all devices that are associated with a given room from the database
pub async fn get_all_devices_inside_room(room_id: i64, pool: &DbConnection) -> Result<Vec<Device>> {
    let device_dbo: Vec<DeviceDbo> = sqlx::query_as!(DeviceDbo, "SELECT * FROM devices WHERE room_id = $1", room_id)
        .fetch_all(pool)
        .await?;

    Ok(device_dbo.into_iter().map(Device::from).collect())
}

///Creates a new room with a given name and color in the database
pub async fn insert_room(room: &Room, pool: &DbConnection) -> Result<u64> {
    let insert = sqlx::query!("INSERT INTO rooms (name, color) VALUES ($1, $2)", room.name, room.color)
        .execute(pool)
        .await?;

    Ok(insert.rows_affected())
}

///Deletes a room with a given name from database
pub async fn delete_room(name: &str, pool: &DbConnection) -> Result<u64> {
    let del_count = sqlx::query!("delete from rooms where name = ?", name)
        .execute(pool)
        .await?;

    Ok(del_count.rows_affected())
}
