use dotenv::dotenv;
use log::info;
use namib_mud_controller::db::DbConnection;
use sqlx::migrate;

#[cfg(feature = "postgres")]
use std::env;

pub struct IntegrationTestContext {
    pub db_url: String,
    pub db_name: &'static str,
    pub db_conn: DbConnection,
}

impl IntegrationTestContext {
    /// Creates a new DB context, so you can access the database.
    /// Added a db_name option, so tests can run parallel and independent
    /// When using SQLite, TESTING_DATABASE_URL is a path where the sqlite files are created
    pub async fn new(db_name: &'static str) -> Self {
        dotenv().ok();
        env_logger::try_init().ok();

        #[cfg(feature = "sqlite")]
        let db_url = "sqlite::memory:".to_string();

        #[cfg(feature = "postgres")]
        let db_url = format!(
            "{}/{}",
            env::var("DATABASE_URL").expect("Failed to load DB URL from .env"),
            db_name
        );

        info!("Using DB {:?}", db_url);

        let db_conn = DbConnection::connect(&db_url)
            .await
            .expect("Couldn't establish connection pool for database");

        #[cfg(feature = "sqlite")]
        migrate!("migrations/sqlite")
            .run(&db_conn)
            .await
            .expect("Database migrations failed");

        #[cfg(feature = "postgres")]
        migrate!("migrations/postgres")
            .run(&db_conn)
            .await
            .expect("Database migrations failed");

        Self {
            db_url,
            db_name,
            db_conn,
        }
    }
}

#[cfg(feature = "postgres")]
impl Drop for IntegrationTestContext {
    /// Removes/cleans the DB context
    fn drop(&self) {
        sqlx::query("DROP DATABASE " + self.db_name);

        info!("Cleaned up database context");
    }
}
