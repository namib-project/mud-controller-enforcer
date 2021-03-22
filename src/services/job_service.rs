use crate::{
    db::DbConnection,
    services::{acme_service, mud_service::mud_profile_service},
};
use clokwerk::{Scheduler, TimeUnits};
use std::{thread, thread::JoinHandle, time::Duration};

/// Create new job scheduler that update the expired mud profiles.
/// conn is the current database connection.
pub fn start_jobs(conn: DbConnection) -> JoinHandle<()> {
    info!("Start scheduler");
    let mut scheduler = Scheduler::new();
    scheduler.every(1.hour()).run(move || {
        let conn = conn.clone();
        actix_rt::spawn(async move {
            if let Err(e) = mud_profile_service::update_outdated_profiles(&conn).await {
                warn!("Failed to update outdated profiles: {:?}", e);
            }
        });
    });
    scheduler.every(6.hours()).run(|| {
        actix_rt::spawn(async {
            if let Err(e) = acme_service::update_certs() {
                warn!("Failed to update certificates: {:?}", e);
            }
        })
    });
    thread::spawn(move || loop {
        debug!("Running pending");
        scheduler.run_pending();
        thread::sleep(Duration::from_secs(600));
    })
}
