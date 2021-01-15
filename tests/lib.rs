use dotenv::dotenv;
use log::info;
use namib_mud_controller::db::ConnectionType;
use sqlx::migrate;

#[cfg(feature = "postgres")]
use std::env;

pub struct IntegrationTestContext {
    pub db_url: String,
    pub db_name: String,
    pub db_pool: Option<ConnectionType>,
}

impl IntegrationTestContext {
    /// Creates a new DB context, so you can access the database.
    /// Added a db_name option, so tests can run parallel and independent
    /// When using SQLite, TESTING_DATABASE_URL is a path where the sqlite files are created
    pub async fn new(db_name: &str) -> Self {
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

        let conn = ConnectionType::connect(&db_url)
            .await
            .expect("Couldn't establish connection pool for database");

        #[cfg(feature = "sqlite")]
        migrate!("migrations/sqlite")
            .run(&conn)
            .await
            .expect("Database migrations failed");

        #[cfg(feature = "postgres")]
        migrate!("migrations/postgres")
            .run(&conn)
            .await
            .expect("Database migrations failed");

        Self {
            db_url,
            db_name: db_name.to_string(),
            db_pool: Some(conn),
        }
    }
}

impl Drop for IntegrationTestContext {
    /// Removes/cleans the DB context
    /// When using SQLite, the database is just getting deleted
    /// TODO: Postgres destruction
    fn drop(&mut self) {
        // let conn = ConnectionType::establish(self.db_url.as_ref()).expect("Couldn't establish connection to database");

        // Closing all connections by destructing db_pool implicitly, so we can delete the db
        self.db_pool = None;

        info!("Cleaned up database context");
    }
}
