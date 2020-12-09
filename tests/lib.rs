use diesel::prelude::*;
use diesel_migrations::embed_migrations;
use dotenv::dotenv;
use log::{debug, info};
use namib_mud_controller::db::DbConn;
use rocket_contrib::databases::{DatabaseConfig, Poolable};
use std::{borrow::Borrow, env, fs};

#[cfg(feature = "sqlite")]
embed_migrations!("migrations/sqlite");

#[cfg(feature = "sqlite")]
pub type ConnectionType = SqliteConnection;

/// The pool type.
pub struct DbConnPool(rocket_contrib::databases::r2d2::Pool<<SqliteConnection as rocket_contrib::databases::Poolable>::Manager>);

impl DbConnPool {
    pub fn get_one(&self) -> Option<DbConn> {
        self.0.get().ok().map(DbConn)
    }
}

impl Clone for DbConnPool {
    fn clone(&self) -> Self {
        DbConnPool(self.0.clone())
    }
}

pub struct DbContext {
    pub db_url: String,
    pub db_name: String,
    pub db_pool: Option<DbConnPool>,
}

impl DbContext {
    /// Creates a new DB context, so you can access the database.
    /// Added a db_name option, so tests can run parallel and independent
    /// When using SQLite, TESTING_DATABASE_URL is a path where the sqlite files are created
    pub fn new(db_name: &str) -> Self {
        dotenv().expect("Failed to read .env file");
        let base_url = env::var("TESTING_DATABASE_URL").expect("Failed to load DB URL from .env");

        #[cfg(feature = "sqlite")]
        let db_url = format!("{}test-{}.db", ensure_trailing_slash(base_url), db_name);

        #[cfg(feature = "postgres")]
        let db_url = format!("{}/{}", base_url, db_name);

        info!("Using DB {:?}", db_url);

        let pool = DbConnPool(
            ConnectionType::pool(DatabaseConfig {
                url: db_url.as_ref(),
                pool_size: 10,
                extras: Default::default(),
            })
            .expect("Couldn't establish connection pool for database"),
        );

        let migration_conn = ConnectionType::establish(db_url.as_ref()).expect("Couldn't establish connection to database");
        embedded_migrations::run(&migration_conn).expect("Couldn't run database migrations");
        drop(migration_conn);

        Self {
            db_url,
            db_name: db_name.to_string(),
            db_pool: Some(pool),
        }
    }
}

impl Drop for DbContext {
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

fn remove_sqlite_db(context: &DbContext) -> () {
    debug!("Removing SQLite DB at {}", context.db_url);
    fs::remove_file(context.db_url.clone()).expect(format!("Couldn't remove SQLite DB at {}", context.db_url).as_ref())
}
