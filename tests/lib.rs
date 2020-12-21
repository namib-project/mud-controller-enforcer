use diesel::prelude::*;
use dotenv::dotenv;
use log::{debug, info};
use namib_mud_controller::db::{run_db_migrations, ConnectionType, DbConnPool};
use rocket_contrib::databases::{DatabaseConfig, Poolable};
use std::{borrow::Borrow, env, fs};

pub struct IntegrationTestContext {
    pub db_url: String,
    pub db_name: String,
    pub db_pool: Option<DbConnPool>,
}

impl IntegrationTestContext {
    /// Creates a new DB context, so you can access the database.
    /// Added a db_name option, so tests can run parallel and independent
    /// When using SQLite, TESTING_DATABASE_URL is a path where the sqlite files are created
    pub fn new(db_name: &str) -> Self {
        dotenv().ok();
        env_logger::try_init().ok();

        let base_url = env::var("TESTING_POSTGRES_URL").expect("Failed to load DB URL from .env");

        #[cfg(feature = "sqlite")]
        let db_url = ":memory:".to_string();

        #[cfg(feature = "postgres")]
        let db_url = format!("{}/{}", base_url, db_name);

        info!("Using DB {:?}", db_url);

        let pool = DbConnPool::new(
            ConnectionType::pool(DatabaseConfig {
                url: db_url.as_ref(),
                pool_size: 10,
                extras: Default::default(),
            })
            .expect("Couldn't establish connection pool for database"),
        );

        // pool::get_one().expect("Couldn't establish connection to database")
        let migration_conn = pool.get_one().expect("Couldn't establish connection to database");
        run_db_migrations(&migration_conn).expect("Database migrations failed");
        drop(migration_conn);

        Self {
            db_url,
            db_name: db_name.to_string(),
            db_pool: Some(pool),
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
