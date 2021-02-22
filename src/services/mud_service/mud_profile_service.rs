use crate::{
    db::DbConnection,
    error::Result,
    models::MudDboRefresh,
    services::{firewall_configuration_service::update_config_version, mud_service::*},
};
use chrono::Utc;
use clokwerk::Scheduler;
use std::{thread, time::Duration};

pub fn job_update_outdated_profiles(conn: DbConnection, interval: clokwerk::Interval, sleep_duration: Duration) {
    log::info!("Start scheduler");
    let mut scheduler = Scheduler::new();
    scheduler.every(interval).run(move || {
        log::info!("Start scheduler every {:?}", interval);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("could not construct tokio runtime")
            .block_on(update_outdated_profiles(&conn))
            .expect("failed running scheduler for update_outdated_profiles");
    });
    loop {
        scheduler.run_pending();
        thread::sleep(sleep_duration);
    }
}

async fn update_outdated_profiles(db_pool: &DbConnection) -> Result<()> {
    log::debug!("Update outdated profiles");
    let mud_data = get_all_mud_expiration(&db_pool).await?;
    let mud_vec: Vec<String> = get_filtered_mud_urls(mud_data);
    update_mud_urls(mud_vec, &db_pool).await?;
    update_config_version(&db_pool).await
}

fn get_filtered_mud_urls(mut mud_vec: Vec<MudDboRefresh>) -> Vec<String> {
    let mut result: Vec<String> = vec![];
    for mud in mud_vec.iter_mut() {
        if mud.expiration < Utc::now().naive_utc() {
            log::debug!("Found outdated mud profile: {}", mud.url);
            mud.expiration = Utc::now().naive_utc();
            result.push(mud.url.to_owned());
        }
    }
    result
}

async fn update_mud_urls(vec_url: Vec<String>, db_pool: &DbConnection) -> Result<()> {
    for mud in vec_url.iter() {
        log::debug!("Try to update url: {}", mud);
        let updated_mud = get_mud_from_url(mud.to_owned(), db_pool).await?;
        log::debug!("Updated mud profile: {:#?}", updated_mud);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDateTime;
    use dotenv::dotenv;
    use sqlx::migrate;

    #[actix_rt::test]
    async fn test_update_outdated_profiles() -> Result<()> {
        let db_conn = init().await?;
        let url = "test_url".to_string();
        let data = "test_data".to_string();
        let created = NaiveDateTime::parse_from_str("2020-11-12T5:52:46", "%Y-%m-%dT%H:%M:%S").unwrap();
        let expiration = NaiveDateTime::parse_from_str("2020-11-12T5:52:46", "%Y-%m-%dT%H:%M:%S").unwrap();
        sqlx::query!(
            "insert into mud_data (url, data, created_at, expiration) values (?, ?, ?, ?)",
            url,
            data,
            created,
            expiration,
        )
        .execute(&db_conn)
        .await?;

        let mud_data = get_all_mud_expiration(&db_conn).await?;
        let vec_mud: Vec<String> = get_filtered_mud_urls(mud_data);
        let url = "test_url".to_string();
        let opt_mud = vec_mud.iter().find(|&u| u == &url);
        assert_eq!(opt_mud, Some(&url));
        sqlx::query!("DELETE FROM mud_data WHERE url = ?", url)
            .execute(&db_conn)
            .await?;

        Ok(())
    }

    async fn init() -> Result<DbConnection> {
        dotenv().ok();
        env_logger::try_init().ok();

        #[cfg(feature = "sqlite")]
        let db_url = "sqlite::memory:".to_string();

        #[cfg(feature = "postgres")]
        let db_url = format!(
            "{}/{}",
            std::env::var("DATABASE_URL").expect("Failed to load DB URL from .env"),
            db_name
        );

        info!("Using DB {:?}", db_url);

        let db_conn = DbConnection::connect(&db_url)
            .await
            .expect("Couldn't establish connection pool for database");

        #[cfg(feature = "sqlite")]
        migrate!("migrations/sqlite")
            .run(&db_conn)
            .await
            .expect("Database migrations failed");

        #[cfg(feature = "postgres")]
        migrate!("migrations/postgres")
            .run(&db_conn)
            .await
            .expect("Database migrations failed");

        Ok(db_conn)
    }
}
