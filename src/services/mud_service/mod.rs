use crate::{
    db::DbConnection,
    error::Result,
    models::{MudData, MudDbo, MudDboRefresh},
};
use chrono::Utc;
use isahc::AsyncReadResponseExt;

mod json_models;
pub mod mud_profile_service;
mod parser;

pub async fn get_mud_from_url(url: String, pool: &DbConnection) -> Result<MudData> {
    // lookup datenbank ob schon existiert und nicht abgelaufen
    let existing_mud: Option<MudDbo> = sqlx::query_as!(MudDbo, "select * from mud_data where url = ?", url)
        .fetch_optional(pool)
        .await?;
    let mut exists = false;
    if let Some(mud) = existing_mud {
        if mud.expiration > Utc::now().naive_utc() {
            if let Ok(mud) = serde_json::from_str::<MudData>(mud.data.as_str()) {
                return Ok(mud);
            }
        }
        exists = true;
    }

    // wenn nicht: fetch
    let mud_json = fetch_mud(url.as_str()).await?;

    // ruf parse_mud auf
    let data = parser::parse_mud(url.clone(), mud_json.as_str())?;

    // speichern in db
    let mud = MudDbo {
        url: url.clone(),
        data: serde_json::to_string(&data)?,
        created_at: Utc::now().naive_utc(),
        expiration: data.expiration.naive_utc(),
    };

    debug!("save mud file (exists: {:?}): {:?}", exists, mud);

    if exists {
        sqlx::query!(
            "update mud_data set data = ?, created_at = ?, expiration = ? where url = ? ",
            mud.data,
            mud.created_at,
            mud.expiration,
            mud.url,
        )
        .execute(pool)
        .await?;
    } else {
        sqlx::query!(
            "insert into mud_data (url, data, created_at, expiration) values (?, ?, ?, ?)",
            mud.url,
            mud.data,
            mud.created_at,
            mud.expiration,
        )
        .execute(pool)
        .await?;
    }

    // return muddata
    Ok(data)
}

async fn fetch_mud(url: &str) -> Result<String> {
    Ok(isahc::get_async(url).await?.text().await?)
}

/// This function return MudDboRefresh they only containing url and expiration
/// to reduce payload.
async fn get_all_mud_expiration(pool: &DbConnection) -> Result<Vec<MudDboRefresh>> {
    let mut mud_profiles = vec![];
    let mud_data = sqlx::query!("select url, expiration from mud_data")
        .fetch_all(pool)
        .await?;
    for mud in mud_data {
        mud_profiles.push(MudDboRefresh {
            url: mud.url,
            expiration: mud.expiration,
        });
    }

    println!("{:?}", mud_profiles);
    Ok(mud_profiles)
}

/// This Function only updating expiration to reduce payload.
async fn refresh_mud_expiration(mud_dbo_vec: Vec<MudDboRefresh>, pool: &DbConnection) -> Result<()> {
    for mud in &mud_dbo_vec {
        sqlx::query!(
            "update mud_data set expiration = ? where url = ? ",
            mud.expiration,
            mud.url,
        )
        .execute(pool)
        .await?;
    }
    Ok(())
}
