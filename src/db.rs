// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use sqlx::migrate;

use crate::{app_config::APP_CONFIG, error::Result};

/// The type of the database connection
#[cfg(feature = "postgres")]
pub type DbConnection = sqlx::PgPool;

/// The type of the database connection
#[cfg(not(feature = "postgres"))]
pub type DbConnection = sqlx::SqlitePool;

/// Connect to the postgres database and run migrations.
#[cfg(feature = "postgres")]
pub async fn connect() -> Result<DbConnection> {
    let conn = sqlx::PgPool::connect(&APP_CONFIG.database_url).await?;
    migrate!("migrations/postgres").run(&conn).await?;
    Ok(conn)
}

/// Connect to the sqlite database and run migrations.
#[cfg(not(feature = "postgres"))]
pub async fn connect() -> Result<DbConnection> {
    let conn = sqlx::SqlitePool::connect(&APP_CONFIG.database_url).await?;
    migrate!("migrations/sqlite").run(&conn).await?;
    Ok(conn)
}
