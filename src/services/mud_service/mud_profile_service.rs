use std::{thread, time::Duration};

use chrono::Utc;
use clokwerk::Scheduler;

use crate::{
    db::DbConnection,
    error::Result,
    models::MudDboRefresh,
    services::{firewall_configuration_service::update_config_version, mud_service::*},
};

pub fn job_update_outdated_profiles(conn: DbConnection, interval: clokwerk::Interval, sleep_duration: Duration) {
    log::info!("Start scheduler");
    let mut scheduler = Scheduler::new();
    scheduler.every(interval).run(move || {
        log::info!("Start scheduler every {:?}", interval);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("could not construct tokio runtime")
            .block_on(update_outdated_profiles(&conn))
            .expect("failed running scheduler for update_outdated_profiles");
    });
    loop {
        scheduler.run_pending();
        thread::sleep(sleep_duration);
    }
}

async fn update_outdated_profiles(db_pool: &DbConnection) -> Result<()> {
    log::debug!("Update outdated profiles");
    let mud_data = get_all_mud_expiration(&db_pool).await?;
    let mud_vec: Vec<String> = get_filtered_mud_urls(mud_data);
    update_mud_urls(mud_vec, &db_pool).await?;
    update_config_version(&db_pool).await
}

fn get_filtered_mud_urls(mut mud_vec: Vec<MudDboRefresh>) -> Vec<String> {
    let mut result: Vec<String> = vec![];
    for mud in mud_vec.iter_mut() {
        if mud.expiration < Utc::now().naive_utc() {
            log::debug!("Found outdated mud profile: {}", mud.url);
            mud.expiration = Utc::now().naive_utc();
            result.push(mud.url.to_owned());
        }
    }
    result
}

async fn update_mud_urls(vec_url: Vec<String>, db_pool: &DbConnection) -> Result<()> {
    for mud_url in vec_url.iter() {
        log::debug!("Try to update url: {}", mud_url);
        let updated_mud = get_mud_from_url(mud_url.to_owned(), db_pool).await?;
        log::debug!("Updated mud profile: {:#?}", updated_mud);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read};

    use chrono::{Duration, NaiveDateTime, Utc};
    use dotenv::dotenv;
    use sqlx::migrate;

    use crate::{
        models::{MudData, MudDbo},
        services::mud_service::parser::parse_mud,
    };

    use super::*;

    #[actix_rt::test]
    async fn test_trivial_functionality() -> Result<()> {
        let db_conn = init().await?;
        let url = "test_url".to_string();
        let data = "test_data".to_string();
        let created = NaiveDateTime::parse_from_str("2020-11-12T5:52:46", "%Y-%m-%dT%H:%M:%S").unwrap();
        let expiration = NaiveDateTime::parse_from_str("2020-11-12T5:52:46", "%Y-%m-%dT%H:%M:%S").unwrap();
        sqlx::query!(
            "insert into mud_data (url, data, created_at, expiration) values (?, ?, ?, ?)",
            url,
            data,
            created,
            expiration,
        )
        .execute(&db_conn)
        .await?;

        let mud_data = get_all_mud_expiration(&db_conn).await?;
        let vec_mud: Vec<String> = get_filtered_mud_urls(mud_data);
        let url = "test_url".to_string();
        let opt_mud = vec_mud.iter().find(|&u| u == &url);
        assert_eq!(opt_mud, Some(&url));
        sqlx::query!("DELETE FROM mud_data WHERE url = ?", url)
            .execute(&db_conn)
            .await?;

        Ok(())
    }

    async fn init() -> Result<DbConnection> {
        dotenv().ok();
        env_logger::try_init().ok();

        #[cfg(feature = "sqlite")]
        let db_url = "sqlite::memory:".to_string();

        #[cfg(feature = "postgres")]
        let db_url = format!(
            "{}/{}",
            std::env::var("DATABASE_URL").expect("Failed to load DB URL from .env"),
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

        Ok(db_conn)
    }

    #[actix_rt::test]
    //tests whether update_outdated_profiles() works on expired profiles. Dependent on external Service.
    async fn test_update_outdated_profiles() -> Result<()> {
        //Sets up an expired Amazon Echo profile
        const PATH: &str = "tests/mud_tests/Amazon-Echo";
        let conn = init().await?;
          //external URL containing the same contents as in the test file. Makes the test dependent on an external Service
        let url: String = String::from("http://iotanalytics.unsw.edu.au/mud/amazonEchoMud.json");
        let mut file = File::open(PATH).expect(format!("Could not open {}", PATH).as_str());
        let mut str_data = String::new();
        file.read_to_string(&mut str_data)
            .expect(format!("Could not read {}", PATH).as_str());
        let mud_json: json_models::MudJson = serde_json::from_str(&str_data)?;
        let duration = mud_json.mud.cache_validity.unwrap_or(48);
        let mud_data: MudData =
            parse_mud(url.clone(), str_data.as_str()).expect(format!("Could not parse {}", PATH).as_str());

        let present = Utc::now();
        let mud_dbo = MudDbo {
            url: url.to_owned(),
            data: serde_json::to_string(&mud_data)?,
            created_at: Utc::now().naive_utc(),
            //the expiration time is set to an arbitrary value that is guaranteed to be prior to the current date
            expiration: (present - Duration::hours(duration)).naive_utc(),
        };

        //Puts expired Profile into the Database
        sqlx::query!(
            "insert into mud_data (url, data, created_at, expiration) values (?, ?, ?, ?)",
            mud_dbo.url,
            mud_dbo.data,
            mud_dbo.created_at,
            mud_dbo.expiration,
        )
        .execute(&conn)
        .await?;

        //function call
        update_outdated_profiles(&conn).await?;

        let new_mud_data: MudDbo = sqlx::query_as!(MudDbo, "SELECT * FROM mud_data WHERE url = $1", mud_data.url)
            .fetch_one(&conn)
            .await?;

        //value slightly below and above the time that the new expiration date should be active for
        let lower_expiration = present.naive_utc() + Duration::hours(duration - 1);
        let higher_expiration = present.naive_utc() + Duration::hours(duration + 1);

        //checks whether the expiration date has been changed
        assert_ne!(new_mud_data.expiration, mud_dbo.expiration);
        //checks whether the new expiration date is more recent than the previous one
        assert!(new_mud_data.expiration > mud_dbo.expiration);
        //checks whether the new expiration date is after the current date
        assert!(new_mud_data.expiration > present.naive_utc());
        //checks whether the new expiration date is within the bounds of the cache validity
        assert!(new_mud_data.expiration > lower_expiration);
        assert!(new_mud_data.expiration < higher_expiration);

        //returns the database to the state before the test
        sqlx::query!("DELETE FROM mud_data WHERE url = ?", mud_dbo.url)
            .execute(&conn)
            .await?;

        let is_delete: Option<MudDbo> = sqlx::query_as!(MudDbo, "SELECT * FROM mud_data WHERE url = ?", mud_data.url)
            .fetch_optional(&conn)
            .await?;

        //makes sure the tests changes to the database are gone
        assert!(is_delete.is_none());
        Ok(())
    }

    #[actix_rt::test]
    //tests whether update_outdated_profiles() doesn't modify profiles that aren't expired yet. Dependent on external Service.
    async fn test_update_valid_profiles() -> Result<()> {
        //Sets up a valid Amazon Echo profile
        const PATH: &str = "tests/mud_tests/Amazon-Echo";
        let conn = init().await?;
        //external URL containing the same contents as in the test file. Makes the test dependent on an external Service
        let url: String = String::from("http://iotanalytics.unsw.edu.au/mud/amazonEchoMud.json");
        let duration: i64 = 50;
        let mut file = File::open(PATH).expect(format!("Could not open {}", PATH).as_str());
        let mut str_data = String::new();
        file.read_to_string(&mut str_data)
            .expect(format!("Could not read {}", PATH).as_str());

        let mud_data: MudData =
            parse_mud(url.clone(), str_data.as_str()).expect(format!("Could not parse {}", PATH).as_str());

        let mud_dbo = MudDbo {
            url: url.to_owned(),
            //the profile content is modified from it's original state to distinguish it from the original
            data: serde_json::to_string(&mud_data)? + "Test",
            created_at: Utc::now().naive_utc(),
            //the expiration time is set to an arbitrary value that is after the current date
            expiration: (Utc::now() + Duration::hours(duration)).naive_utc(),
        };

        //Puts active Profile into the Database
        sqlx::query!(
            "insert into mud_data (url, data, created_at, expiration) values (?, ?, ?, ?)",
            mud_dbo.url,
            mud_dbo.data,
            mud_dbo.created_at,
            mud_dbo.expiration,
        )
        .execute(&conn)
        .await?;

        //function call
        update_outdated_profiles(&conn).await?;

        let new_mud_data: MudDbo = sqlx::query_as!(MudDbo, "SELECT * FROM mud_data WHERE url = $1", mud_data.url)
            .fetch_one(&conn)
            .await?;

        //checks whether the expiration date has not been changed
        assert_eq!(new_mud_data.expiration, mud_dbo.expiration);
        //checks that the contents of the profile have not been updated
        assert_eq!(
            serde_json::to_string(&new_mud_data).unwrap(),
            serde_json::to_string(&mud_dbo).unwrap()
        );
        //checks whether the expiration date is after the current date
        assert!(new_mud_data.expiration > Utc::now().naive_utc());

        //returns the database to the state before the test
        sqlx::query!("DELETE FROM mud_data WHERE url = ?", mud_dbo.url)
            .execute(&conn)
            .await?;

        let is_delete: Option<MudDbo> = sqlx::query_as!(MudDbo, "SELECT * FROM mud_data WHERE url = ?", mud_data.url)
            .fetch_optional(&conn)
            .await?;

        //makes sure the tests changes to the database are gone
        assert!(is_delete.is_none());
        Ok(())
    }
}
