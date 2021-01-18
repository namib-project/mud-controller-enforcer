use crate::{db::ConnectionType, error::Result, models::Config};

/// Gets the config value by key from the database.
pub async fn get_config_value(key: String, pool: &ConnectionType) -> Result<String> {
    let entry = sqlx::query_as!(Config, "SELECT * FROM config WHERE key = ?", key)
        .fetch_one(pool)
        .await?;

    Ok(entry.value)
}

/// Writes the config value by key to the database.
/// Upserts the value by key
pub async fn set_config_value(key: String, value: String, pool: &ConnectionType) -> Result<()> {
    let _ins_count = sqlx::query!(
        "INSERT INTO config VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        key,
        value,
    )
    .execute(pool)
    .await?;

    // Ok(ins_count.rows_affected())
    Ok(())
}

pub async fn delete_config_key(key: String, pool: &ConnectionType) -> Result<()> {
    let _del_count = sqlx::query!("DELETE FROM config WHERE key = ?", key)
        .execute(pool)
        .await?;

    // Ok(del_count.rows_affected())
    Ok(())
}
