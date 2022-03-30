// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::time::Duration;

use clokwerk::{Scheduler, TimeUnits};
use tokio::time::sleep;

use crate::{
    app_config::APP_CONFIG,
    db::DbConnection,
    services::{acme_service, device_config_service, mud_service},
};

/// Create new job scheduler that update the expired mud profiles.
/// conn is the current database connection.
pub async fn start_jobs(conn: DbConnection) {
    if let Err(err) =
        device_config_service::update_device_configurations_from_file(&conn, &APP_CONFIG.namib_device_config).await
    {
        let current_dir = match std::env::current_dir() {
            Ok(dir) => dir.to_str().unwrap_or("[unknown]").to_string(),
            Err(_) => "[unknown]".to_string(),
        };
        warn!(
            "Unable to load device configuration from file: '{}' (in cwd '{}')",
            err, current_dir
        );
    }

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
