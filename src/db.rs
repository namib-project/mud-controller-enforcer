use rand::{thread_rng, RngCore};
use sqlx::migrate;

use crate::{
    app_config::APP_CONFIG,
    error::{Error::DatabaseError, Result},
    services::config_service::{get_config_value, set_config_value},
};

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
    initialize_jwt_secret(&conn).await?;
    Ok(conn)
}

/// Connect to the sqlite database and run migrations.
#[cfg(not(feature = "postgres"))]
pub async fn connect() -> Result<DbConnection> {
    let conn = sqlx::SqlitePool::connect(&APP_CONFIG.database_url).await?;
    migrate!("migrations/sqlite").run(&conn).await?;
    initialize_jwt_secret(&conn).await?;
    Ok(conn)
}

pub async fn initialize_jwt_secret(conn: &DbConnection) -> Result<()> {
    let jwt_secret: Result<String> = get_config_value("jwt_secret", &conn).await;
    match jwt_secret {
        Err(DatabaseError {
            source: sqlx::error::Error::RowNotFound,
            backtrace: _,
        }) => {
            let mut jwt_secret = [0; 256];
            thread_rng().fill_bytes(&mut jwt_secret);
            set_config_value("jwt_secret", base64::encode(&jwt_secret), &conn).await?;
            Ok(())
        },
        x => x.map(|_v| ()),
    }
}
