use crate::{db::DbConnPool, error::Result, models::config_model::Config, schema::config};
use diesel::prelude::*;

/// Gets the config value by key from the database.
pub async fn get_config_value(key: String, pool: DbConnPool) -> Result<String> {
    let conn = pool.get_one().expect("couldn't get db conn from pool");
    let config_entry = config::table.find(key).get_result::<Config>(&*conn)?;

    Ok(config_entry.value)
}

/// Writes the config value by key to the database.
/// Checks if the key already exists.
/// If yes: Updates the value. If no: Inserts the value
pub async fn set_config_value(key: String, value: String, pool: DbConnPool) -> Result<()> {
    let conn = pool.get_one().expect("couldn't get db conn from pool");

    match get_config_value(key.clone(), pool).await {
        Ok(_) => diesel::update(config::table.find(&key))
            .set(Config {
                key: key.clone(),
                value: value.clone(),
            })
            .execute(&*conn)?,
        Err(_) => diesel::insert_into(config::table)
            .values(Config {
                key: key.clone(),
                value: value.clone(),
            })
            .execute(&*conn)?,
    };

    Ok(())
}

pub async fn delete_config_key(key: String, pool: DbConnPool) -> Result<()> {
    let conn = pool.get_one().expect("couldn't get db conn from pool");

    diesel::delete(config::table.filter(config::key.eq(&key))).execute(&*conn)?;

    Ok(())
}
