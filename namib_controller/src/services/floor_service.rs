// Copyright 2022, Matthias Reichmann
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    db::DbConnection,
    error::Result,
    models::{Room, Floor},
};

///returns all floors from the database
pub async fn get_all_floors(pool: &DbConnection) -> Result<Vec<Floor>> {
    let floor_data = sqlx::query_as!(Floor, "SELECT * FROM floors").fetch_all(pool).await?;

    Ok(floor_data)
}

///returns floor by id from the database
pub async fn find_by_id(id: i64, pool: &DbConnection) -> Result<Floor> {
    let floor = sqlx::query_as!(Floor, "SELECT * FROM floors WHERE id = $1", id)
        .fetch_one(pool)
        .await?;

    Ok(floor)
}

///returns floor by label from the database
pub async fn find_by_label(label: &str, pool: &DbConnection) -> Result<Floor> {
    let floor = sqlx::query_as!(Floor, "SELECT * FROM floors WHERE label = $1", label)
        .fetch_one(pool)
        .await?;

    Ok(floor)
}

///updates a floor with a new name and color in the database
pub async fn update(floor: &Floor, pool: &DbConnection) -> Result<bool> {
    let upd_count = sqlx::query!(
        "UPDATE floors SET label = $1 WHERE id = $2",
        floor.label,
        floor.id
    )
    .execute(pool)
    .await?;

    Ok(upd_count.rows_affected() == 1)
}

///returns all rooms that are associated with a given floor from the database
pub async fn get_all_rooms_of_floor(floor_id: i64, pool: &DbConnection) -> Result<Vec<Room>> {
    let device_dbo: Vec<Room> = sqlx::query_as!(Room, "SELECT r.*, f.label floor_label FROM rooms r
        JOIN floors f ON f.id = r.floor_id WHERE floor_id = $1", floor_id)
        .fetch_all(pool)
        .await?;

    Ok(device_dbo)
}

///Creates a new floor with a given label in the database
pub async fn insert_floor(floor: &Floor, pool: &DbConnection) -> Result<u64> {
    let insert = sqlx::query!("INSERT INTO floors (label) VALUES ($1)", floor.label)
        .execute(pool)
        .await?;

    Ok(insert.rows_affected())
}

///Deletes a floor with a given label from database
pub async fn delete_floor(label: &str, pool: &DbConnection) -> Result<u64> {
    let del_count = sqlx::query!("DELETE FROM floors WHERE label = $1", label)
        .execute(pool)
        .await?;

    Ok(del_count.rows_affected())
}
