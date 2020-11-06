use diesel::prelude::*;
use rocket::Rocket;
use rocket_contrib::database;

// This macro from `diesel_migrations` defines an `embedded_migrations` module
// containing a function named `run`. This allows the example to be run and
// tested without any outside setup of the database.
#[cfg(feature = "postgres")]
embed_migrations!("migrations/postgres");

#[cfg(feature = "postgres")]
#[database("postgres")]
pub struct DbConn(PgConnection);

#[cfg(feature = "postgres")]
pub type ConnectionType = PgConnection;

#[cfg(feature = "sqlite")]
embed_migrations!("migrations/sqlite");

#[cfg(feature = "sqlite")]
#[database("sqlite_db")]
pub struct DbConn(SqliteConnection);

#[cfg(feature = "sqlite")]
pub type ConnectionType = SqliteConnection;

pub fn run_db_migrations(rocket: Rocket) -> Result<Rocket, Rocket> {
    let conn = DbConn::get_one(&rocket).expect("database connection");
    match embedded_migrations::run(&*conn) {
        Ok(()) => Ok(rocket),
        Err(e) => {
            error!("Failed to run database migrations: {:?}", e);
            Err(rocket)
        }
    }
}
