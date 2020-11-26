use crate::{db::DbConnPool, error::Result, models::config_model::Config, schema::config};
use diesel::prelude::*;

pub async fn get_config_value(key: String, pool: DbConnPool) -> Result<String> {
    let conn = pool.get_one().expect("couldn't get db conn from pool");
    let config_entry = config::table.find(key).get_result::<Config>(&*conn)?;

    Ok(config_entry.value)
}

pub async fn set_config_value(key: String, value: String, pool: DbConnPool) -> Result<()> {
    let conn = pool.get_one().expect("couldn't get db conn from pool");

    match get_config_value(key.clone(), pool.clone()).await {
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
