// Copyright 2020-2022, Matthias Reichmann
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    db::DbConnection,
    error::Result,
    models::{Notification},
};

///returns all notifications from the database
pub async fn get_all_notifications(pool: &DbConnection) -> Result<Vec<Notification>> {
    let notification_data = sqlx::query_as!(Notification, "SELECT * FROM notifications ORDER BY timestamp DESC")
        .fetch_all(pool)
        .await?;

    Ok(notification_data)
}

///returns notification by id from the database
pub async fn find_by_id(id: i64, pool: &DbConnection) -> Result<Notification> {
    let notification = sqlx::query_as!(Notification, "SELECT * FROM notifications WHERE id = $1", id)
        .fetch_one(pool)
        .await?;

    Ok(notification)
}

///marks a notification as read
pub async fn mark_as_read(notification: &Notification, pool: &DbConnection) -> Result<bool> {
    let upd_count = sqlx::query!(
        "UPDATE notifications SET read = TRUE WHERE id = $1",
        notification.id
    )
    .execute(pool)
    .await?;

    Ok(upd_count.rows_affected() == 1)
}

///Creates a new notification in the database
pub async fn insert_notification(notification: &Notification, pool: &DbConnection) -> Result<i64> {
    let insert = sqlx::query!("INSERT INTO notifications (device_id, source, timestamp, read) VALUES ($1, $2, $3, $4) RETURNING id",
        notification.device_id, notification.source, notification.timestamp, notification.read)
        .fetch_one(pool)
        .await?
        .id;

    Ok(insert)
}

///Deletes a notification from database
pub async fn delete_notification(notification: &Notification, pool: &DbConnection) -> Result<u64> {
    let del_count = sqlx::query!("DELETE FROM notifications WHERE id = $1", notification.id)
        .execute(pool)
        .await?;

    Ok(del_count.rows_affected())
}
