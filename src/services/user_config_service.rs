use crate::{db::DbConnection, error::Result, models::UserConfig};
use sqlx::Done;

pub async fn get_all_configs_for_user(user_id: i64, conn: &DbConnection) -> Result<Vec<UserConfig>> {
    Ok(
        sqlx::query_as!(UserConfig, "SELECT * FROM user_configs WHERE user_id = $1", user_id)
            .fetch_all(conn)
            .await?,
    )
}

pub async fn get_config_for_user(user_id: i64, key: &str, conn: &DbConnection) -> Result<UserConfig> {
    Ok(sqlx::query_as!(
        UserConfig,
        "SELECT * FROM user_configs WHERE user_id = $1 AND key = $2",
        user_id,
        key
    )
    .fetch_one(conn)
    .await?)
}

pub async fn upsert_config_for_user(user_id: i64, key: &str, value: &str, conn: &DbConnection) -> Result<()> {
    sqlx::query!(
        "INSERT INTO user_configs VALUES ($1, $2, $3) ON CONFLICT(user_id, key) DO UPDATE SET value = excluded.value",
        key,
        user_id,
        value,
    )
    .execute(conn)
    .await?;

    Ok(())
}

pub async fn delete_config_for_user(user_id: i64, key: &str, conn: &DbConnection) -> Result<bool> {
    let del_count = sqlx::query!("DELETE FROM user_configs WHERE key = $1 AND user_id = $2", key, user_id)
        .execute(conn)
        .await?;

    debug!("Deleting key {:?} for user {:?}", key, user_id);

    Ok(del_count.rows_affected() == 1)
}
