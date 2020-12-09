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

        let base_url = env::var("TESTING_DATABASE_URL").expect("Failed to load DB URL from .env");

        #[cfg(feature = "sqlite")]
        let db_url = format!("{}test-{}.db", ensure_trailing_slash(base_url), db_name);

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
        let migration_conn = ConnectionType::establish(db_url.as_ref()).expect("Couldn't establish connection to database");
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

        #[cfg(feature = "sqlite")]
        remove_sqlite_db(self.borrow());
        info!("Cleaned up database context");
    }
}

/// Ensures that given string has a trailing slash, if not: returns the string with a trailing slash
fn ensure_trailing_slash(input: String) -> String {
    let last_char = match input.chars().last() {
        Some(char) => char,
        None => return "".to_string(),
    };

    match last_char == '/' {
        true => input,
        false => input + "/",
    }
}

/// Basic wrapper for deleting a SQLite Database at given IntegrationTestContext db_url path
fn remove_sqlite_db(context: &IntegrationTestContext) -> () {
    debug!("Removing SQLite DB at {}", context.db_url);
    fs::remove_file(context.db_url.clone()).expect(format!("Couldn't remove SQLite DB at {}", context.db_url).as_ref())
}
