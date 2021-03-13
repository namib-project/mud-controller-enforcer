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

#[cfg(test)]
pub mod test {
    use crate::{db::DbConnection, error::Result};
    use dotenv::dotenv;
    use sqlx::migrate;

    pub async fn init(db_name: &str) -> Result<DbConnection> {
        dotenv().ok();
        env_logger::try_init().ok();

        let db_url = if cfg!(feature = "sqlite") {
            "sqlite::memory:".to_string()
        } else {
            format!(
                "{}/{}",
                std::env::var("DATABASE_URL").expect("Failed to load DB URL from .env"),
                db_name
            )
        };

        info!("Using DB {:?}", db_url);

        let db_conn = DbConnection::connect(&db_url)
            .await
            .expect("Couldn't establish connection pool for database");

        #[cfg(feature = "sqlite")]
        {
            migrate!("migrations/sqlite")
                .run(&db_conn)
                .await
                .expect("Database migrations failed");
        }

        #[cfg(feature = "postgres")]
        {
            migrate!("migrations/postgres")
                .run(&db_conn)
                .await
                .expect("Database migrations failed");
        }

        Ok(db_conn)
    }
}
