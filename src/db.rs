use crate::error::Result;
use sqlx::{migrate, SqlitePool};
use std::env;

#[cfg(feature = "postgres")]
pub type ConnectionType = PgConnection;

#[cfg(feature = "sqlite")]
pub type ConnectionType = SqlitePool;

#[cfg(feature = "postgres")]
pub async fn connect() {}

#[cfg(feature = "sqlite")]
pub async fn connect() -> Result<ConnectionType> {
    let conn = SqlitePool::connect(&env::var("DATABASE_URL").expect("DATABASE_URL is not set")).await?;
    migrate!("migrations/sqlite").run(&conn).await?;
    Ok(conn)
}
