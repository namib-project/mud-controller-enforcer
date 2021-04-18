use dotenv::dotenv;
use log::info;
use namib_mud_controller::db::DbConnection;
use sqlx::migrate;

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

        #[cfg(not(feature = "postgres"))]
        let db_url = "sqlite::memory:".to_string();

        #[cfg(feature = "postgres")]
        let db_url = {
            let mut url =
                url::Url::parse(&std::env::var("DATABASE_URL").expect("Failed to load DB URL from .env")).unwrap();
            let db_name = format!("__{}", db_name);
            let conn = DbConnection::connect(url.as_str()).await.unwrap();
            sqlx::query(&format!("DROP DATABASE IF EXISTS {}", db_name))
                .execute(&conn)
                .await
                .unwrap();
            sqlx::query(&format!("CREATE DATABASE {}", db_name))
                .execute(&conn)
                .await
                .unwrap();
            url.set_path(&db_name);
            url.to_string()
        };

        info!("Using DB {:?}", db_url);

        let db_conn = DbConnection::connect(&db_url)
            .await
            .expect("Couldn't establish connection pool for database");

        #[cfg(not(feature = "postgres"))]
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
