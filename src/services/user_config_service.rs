use sqlx::Done;
use crate::error::Result;
use crate::{db::DbConnection, error, models::UserConfig};

pub async fn get_all_configs_for_user(user_id: i64, conn: &DbConnection) -> Result<Vec<UserConfig>> {
    Ok(
        sqlx::query_as!(UserConfig, "select * from user_configs where user_id = ?", user_id)
            .fetch_all(conn)
            .await?,
    )
}

pub async fn get_config_for_user(user_id: i64, key: &str, conn: &DbConnection) -> Result<UserConfig> {
    Ok(sqlx::query_as!(
        UserConfig,
        "select * from user_configs where user_id = ? and key = ?",
        user_id,
        key
    )
    .fetch_one(conn)
    .await?)
}

pub async fn upsert_config_for_user(user_id: i64, key: &str, value: &str, conn: &DbConnection) -> Result<()> {
    let _ = sqlx::query!(
        "INSERT INTO user_configs VALUES (?, ?, ?) ON CONFLICT(user_id, key) DO UPDATE SET value = excluded.value",
        key,
        user_id,
        value,
    )
    .execute(conn)
    .await?;

    Ok(())
}

pub async fn delete_config_for_user(user_id: i64, key: &str, conn: &DbConnection) -> Result<u64> {
    let del_count = sqlx::query!("delete from user_configs where key = ? and user_id = ?", key, user_id)
        .execute(conn)
        .await?;

    debug!("Deleting key {:?} for user {:?}", key, user_id);

    Ok(del_count.rows_affected())
}
