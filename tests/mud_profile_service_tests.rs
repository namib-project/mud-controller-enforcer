mod lib;

use std::{fs::File, io::Read};

use chrono::{Duration, Utc};

use actix_web::web;
use namib_mud_controller::{
    auth::AuthToken,
    error::Result,
    models::{MudData, MudDbo},
    routes::{dtos::MudCreationDto, mud_controller},
    services::mud_service::{json_models, mud_profile_service::update_outdated_profiles, parser::parse_mud},
};

#[tokio::test(flavor = "multi_thread")]
async fn test_create_mud() -> Result<()> {
    let ctx = lib::IntegrationTestContext::new("test_create_mud").await;

    mud_controller::create_mud(
        web::Data::new(ctx.db_conn),
        AuthToken::generate_access_token(1, "admin".to_string(), vec!["**".to_string()]),
        web::Json(MudCreationDto {
            mud_url: "Some Mud".to_string(),
            acl_override: Some(
                serde_json::from_str(
                    r#"[
  {
    "acl_type": "IPV4",
    "name": "from-ipv4-amazonecho",
    "packet_direction": "FromDevice",
    "ace": [
      {
        "name": "from-ipv4-amazonecho-1",
        "action": "Accept",
        "matches": {
          "address_mask": null,
          "direction_initiated": "FromDevice",
          "dnsname": "softwareupdates.amazon.com",
          "protocol": { "name": "Protocol", "num": 6 },
          "destination_port": { "single": 443 },
          "source_port": null
        }
      },
      {
        "name": "from-ipv4-amazonecho-2",
        "action": "Accept",
        "matches": {
          "address_mask": null,
          "direction_initiated": null,
          "dnsname": "3.north-america.pool.ntp.org",
          "protocol": { "name": "Protocol", "num": 17 },
          "destination_port": { "single": 123 },
          "source_port": null
        }
      }
    ]
  },
  {
    "acl_type": "IPV6",
    "name": "from-ethernet-amazonecho",
    "packet_direction": "FromDevice",
    "ace": [
      {
        "name": "from-ethernet-amazonecho-0",
        "action": "Accept",
        "matches": {
          "address_mask": null,
          "direction_initiated": null,
          "dnsname": null,
          "protocol": null,
          "destination_port": null,
          "source_port": null
        }
      },
      {
        "name": "from-ethernet-amazonecho-1",
        "action": "Accept",
        "matches": {
          "address_mask": null,
          "direction_initiated": null,
          "dnsname": null,
          "protocol": null,
          "destination_port": null,
          "source_port": null
        }
      }
    ]
  },
  {
    "acl_type": "IPV4",
    "name": "to-ipv4-amazonecho",
    "packet_direction": "ToDevice",
    "ace": [
      {
        "name": "to-ipv4-amazonecho-0",
        "action": "Accept",
        "matches": {
          "address_mask": null,
          "direction_initiated": null,
          "dnsname": "3.north-america.pool.ntp.org",
          "protocol": { "name": "Protocol", "num": 17 },
          "destination_port": null,
          "source_port": { "single": 123 }
        }
      },
      {
        "name": "to-ipv4-amazonecho-1",
        "action": "Accept",
        "matches": {
          "address_mask": null,
          "direction_initiated": null,
          "dnsname": "ntp-g7g.amazon.com",
          "protocol": { "name": "Protocol", "num": 17 },
          "destination_port": null,
          "source_port": { "single": 123 }
        }
      },
      {
        "name": "to-ipv4-amazonecho-2",
        "action": "Accept",
        "matches": {
          "address_mask": null,
          "direction_initiated": null,
          "dnsname": "api.amazonalexa.com",
          "protocol": { "name": "Protocol", "num": 6 },
          "destination_port": null,
          "source_port": { "single": 443 }
        }
      }
    ]
  }
]
"#,
                )
                .unwrap(),
            ),
        }),
    )
    .await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
//tests whether update_outdated_profiles() works on expired profiles. Dependent on external Service.
async fn test_update_outdated_profiles() -> Result<()> {
    //Sets up an expired Amazon Echo profile
    const PATH: &str = "tests/mud_tests/Amazon-Echo.json";
    let ctx = lib::IntegrationTestContext::new("test_update_outdated_profiles").await;
    //external URL containing the same contents as in the test file. Makes the test dependent on an external Service
    let url: String = String::from("http://iotanalytics.unsw.edu.au/mud/amazonEchoMud.json");
    let mut file = File::open(PATH).unwrap_or_else(|_| panic!("Could not open {}", PATH));
    let mut str_data = String::new();
    file.read_to_string(&mut str_data)
        .unwrap_or_else(|_| panic!("Could not read {}", PATH));
    let mud_json: json_models::MudJson = serde_json::from_str(&str_data)?;
    let duration = mud_json.mud.cache_validity.unwrap_or(48);
    let mud_data: MudData =
        parse_mud(url.clone(), str_data.as_str()).unwrap_or_else(|_| panic!("Could not parse {}", PATH));

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
    .execute(&ctx.db_conn)
    .await?;

    //function call
    update_outdated_profiles(&&ctx.db_conn).await?;

    let new_mud_data: MudDbo = sqlx::query_as!(MudDbo, "SELECT * FROM mud_data WHERE url = $1", mud_data.url)
        .fetch_one(&ctx.db_conn)
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
        .execute(&ctx.db_conn)
        .await?;

    let is_delete: Option<MudDbo> = sqlx::query_as!(MudDbo, "SELECT * FROM mud_data WHERE url = ?", mud_data.url)
        .fetch_optional(&ctx.db_conn)
        .await?;

    //makes sure the tests changes to the database are gone
    assert!(is_delete.is_none());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
//tests whether update_outdated_profiles() doesn't modify profiles that aren't expired yet. Dependent on external Service.
async fn test_update_valid_profiles() -> Result<()> {
    //Sets up a valid Amazon Echo profile
    const PATH: &str = "tests/mud_tests/Amazon-Echo.json";
    let ctx = lib::IntegrationTestContext::new("test_update_valid_profiles").await;
    //external URL containing the same contents as in the test file. Makes the test dependent on an external Service
    let url: String = String::from("http://iotanalytics.unsw.edu.au/mud/amazonEchoMud.json");
    let duration: i64 = 50;
    let mut file = File::open(PATH).unwrap_or_else(|_| panic!("Could not open {}", PATH));
    let mut str_data = String::new();
    file.read_to_string(&mut str_data)
        .unwrap_or_else(|_| panic!("Could not read {}", PATH));

    let mud_data: MudData =
        parse_mud(url.clone(), str_data.as_str()).unwrap_or_else(|_| panic!("Could not parse {}", PATH));

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
    .execute(&ctx.db_conn)
    .await?;

    //function call
    update_outdated_profiles(&ctx.db_conn).await?;

    let new_mud_data: MudDbo = sqlx::query_as!(MudDbo, "SELECT * FROM mud_data WHERE url = $1", mud_data.url)
        .fetch_one(&ctx.db_conn)
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
        .execute(&ctx.db_conn)
        .await?;

    let is_delete: Option<MudDbo> = sqlx::query_as!(MudDbo, "SELECT * FROM mud_data WHERE url = ?", mud_data.url)
        .fetch_optional(&ctx.db_conn)
        .await?;

    //makes sure the tests changes to the database are gone
    assert!(is_delete.is_none());
    Ok(())
}
