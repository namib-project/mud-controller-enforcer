use std::env;

use sqlx::migrate;

use crate::error::Result;

/// The type of the database connection
#[cfg(feature = "postgres")]
pub type DbConnection = sqlx::PgPool;

/// The type of the database connection
#[cfg(not(feature = "postgres"))]
pub type DbConnection = sqlx::SqlitePool;

/// Connect to the postgres database and run migrations.
#[cfg(feature = "postgres")]
pub async fn connect() -> Result<DbConnection> {
    let conn = sqlx::PgPool::connect(&env::var("DATABASE_URL").expect("DATABASE_URL is not set")).await?;
    migrate!("migrations/postgres").run(&conn).await?;
    Ok(conn)
}

/// Connect to the sqlite database and run migrations.
#[cfg(not(feature = "postgres"))]
pub async fn connect() -> Result<DbConnection> {
    let conn = sqlx::SqlitePool::connect(&env::var("DATABASE_URL").expect("DATABASE_URL is not set")).await?;
    migrate!("migrations/sqlite").run(&conn).await?;
    Ok(conn)
}
