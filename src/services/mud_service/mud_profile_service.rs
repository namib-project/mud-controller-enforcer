use std::{thread, time::Duration};

use chrono::Utc;
use clokwerk::Scheduler;

use crate::{
    db::DbConnection,
    error::Result,
    services::{firewall_configuration_service::update_config_version, mud_service::*},
};

/// Create new job scheduler that update the expired mud profiles.
/// conn is the current database connection.
/// Interval is the interval at which the profiles are tested.
/// sleep_duration specifies how long the thread should sleep.
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

pub async fn update_outdated_profiles(db_pool: &DbConnection) -> Result<()> {
    log::debug!("Update outdated profiles");
    let mud_data = get_all_mud_expiration(&db_pool).await?;
    let mud_vec: Vec<String> = mud_data
        .into_iter()
        .filter(|mud| mud.expiration < Utc::now().naive_utc())
        .map(|mud| mud.url)
        .collect();
    update_mud_urls(mud_vec, &db_pool).await?;
    update_config_version(&db_pool).await
}

async fn update_mud_urls(vec_url: Vec<String>, db_pool: &DbConnection) -> Result<()> {
    for mud_url in vec_url {
        log::debug!("Try to update url: {}", mud_url);
        let updated_mud = get_or_fetch_mud(mud_url, db_pool).await?;
        log::debug!("Updated mud profile: {:#?}", updated_mud);
    }
    Ok(())
}
