use crate::error::Result;
use sqlx::migrate;
use std::env;

#[cfg(feature = "postgres")]
pub type DbConnection = sqlx::PgPool;

#[cfg(feature = "sqlite")]
pub type DbConnection = sqlx::SqlitePool;

#[cfg(feature = "postgres")]
pub async fn connect() -> Result<DbConnection> {
    let conn = sqlx::PgPool::connect(&env::var("DATABASE_URL").expect("DATABASE_URL is not set")).await?;
    migrate!("migrations/postgres").run(&conn).await?;
    Ok(conn)
}

#[cfg(feature = "sqlite")]
pub async fn connect() -> Result<DbConnection> {
    let conn = sqlx::SqlitePool::connect(&env::var("DATABASE_URL").expect("DATABASE_URL is not set")).await?;
    migrate!("migrations/sqlite").run(&conn).await?;
    Ok(conn)
}
