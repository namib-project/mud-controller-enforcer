use std::time::Duration;

use clokwerk::{Scheduler, TimeUnits};
use tokio::time::sleep;

use crate::{
    db::DbConnection,
    services::{acme_service, mud_service},
};

/// Create new job scheduler that update the expired mud profiles.
/// conn is the current database connection.
pub async fn start_jobs(conn: DbConnection) {
    info!("Start scheduler");
    let mut scheduler = Scheduler::new();
    scheduler.every(1.hour()).run(move || {
        let conn = conn.clone();
        tokio::spawn(async move {
            if let Err(e) = mud_service::update_outdated_profiles(&conn).await {
                warn!("Failed to update outdated profiles: {:?}", e);
            }
        });
    });
    scheduler.every(6.hours()).run(|| {
        tokio::spawn(async {
            if let Err(e) = acme_service::update_certs() {
                warn!("Failed to update certificates: {:?}", e);
            }
        });
    });
    loop {
        debug!("Running pending");
        scheduler.run_pending();
        sleep(Duration::from_secs(600)).await;
    }
}
