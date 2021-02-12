use sqlx::Done;

use crate::{db::DbConnection, error, models::UserConfig};

pub async fn get_all_configs_for_user(user_id: i64, conn: &DbConnection) -> error::Result<Vec<UserConfig>> {
    Ok(
        sqlx::query_as!(UserConfig, "select * from user_configs where user_id = ?", user_id)
            .fetch_all(conn)
            .await?,
    )
}

pub async fn get_config_for_user(user_id: i64, key: &str, conn: &DbConnection) -> error::Result<UserConfig> {
    Ok(sqlx::query_as!(
        UserConfig,
        "select * from user_configs where user_id = ? and key = ?",
        user_id,
        key
    )
    .fetch_one(conn)
    .await?)
}

async fn update_config_for_user(user_id: i64, key: &str, value: &str, conn: &DbConnection) -> error::Result<u64> {
    let upd_count = sqlx::query!(
        "update user_configs set value = ? where key = ? and user_id = ?",
        value,
        key,
        user_id
    )
    .execute(conn)
    .await?;

    debug!("Updating key {:?} with value {:?} for user {:?}", key, value, user_id);

    Ok(upd_count.rows_affected())
}

async fn add_config_for_user(user_id: i64, key: &str, value: &str, conn: &DbConnection) -> error::Result<u64> {
    let ins_count = sqlx::query!(
        "insert into user_configs (key, user_id, value) values (?, ?, ?)",
        key,
        user_id,
        value
    )
    .execute(conn)
    .await?;

    debug!("Inserting key {:?} with value {:?} for user {:?}", key, value, user_id);

    Ok(ins_count.rows_affected())
}

pub async fn upsert_config_for_user(user_id: i64, key: &str, value: &str, conn: &DbConnection) -> error::Result<u64> {
    let existing_config: Vec<UserConfig> = sqlx::query_as!(
        UserConfig,
        "select * from user_configs where user_id = ? and key = ?",
        user_id,
        key
    )
    .fetch_all(conn)
    .await?;

    return if existing_config.is_empty() {
        Ok(add_config_for_user(user_id, key, value, conn).await?)
    } else {
        Ok(update_config_for_user(user_id, key, value, conn).await?)
    };
}

pub async fn delete_config_for_user(user_id: i64, key: &str, conn: &DbConnection) -> error::Result<u64> {
    let del_count = sqlx::query!("delete from user_configs where key = ? and user_id = ?", key, user_id)
        .execute(conn)
        .await?;

    debug!("Deleting key {:?} for user {:?}", key, user_id);

    Ok(del_count.rows_affected())
}
