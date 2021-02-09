use chrono::{DateTime, Local, NaiveDate, TimeZone, Utc};
use isahc::AsyncReadResponseExt;
use lazy_static::lazy_static;
use regex::Regex;

use crate::{
    db::DbConnection,
    error::Result,
    models::{Acl, MudData, MudDbo},
};
use sqlx::Done;

mod json_models;
mod parser;

/// Writes the MudDbo to the database.
/// Upserts data by MudDBO::url
pub async fn upsert_mud(mud_profile: &MudDbo, pool: &DbConnection) -> Result<()> {
    let _ins_count = sqlx::query!(
        "INSERT INTO mud_data (url, data, created_at, expiration, acl_override) VALUES (?, ?, ?, ?, ?) ON CONFLICT(url) DO UPDATE SET data = excluded.data, created_at = excluded.created_at, expiration = excluded.expiration, acl_override = excluded.acl_override",
        mud_profile.url,
        mud_profile.data,
        mud_profile.created_at,
        mud_profile.expiration,
        mud_profile.acl_override,
    )
        .execute(pool)
        .await?;

    // Ok(ins_count.rows_affected())
    Ok(())
}

pub async fn create_mud(mud_profile: &MudDbo, pool: &DbConnection) -> Result<()> {
    let _ins_count = sqlx::query!(
        "INSERT INTO mud_data (url, data, created_at, expiration, acl_override) VALUES (?, ?, ?, ?, ?)",
        mud_profile.url,
        mud_profile.data,
        mud_profile.created_at,
        mud_profile.expiration,
        mud_profile.acl_override,
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_mud(url: &str, pool: &DbConnection) -> Option<MudDbo> {
    sqlx::query_as!(MudDbo, "SELECT * FROM mud_data WHERE url = ?", url)
        .fetch_optional(pool)
        .await
        .ok()?
}

pub async fn get_all_muds(pool: &DbConnection) -> Result<Vec<MudDbo>> {
    let data = sqlx::query_as!(MudDbo, "SELECT * FROM mud_data")
        .fetch_all(pool)
        .await?;

    Ok(data)
}

pub async fn delete_mud(url: &str, pool: &DbConnection) -> Result<u64> {
    let del_count = sqlx::query!("DELETE FROM mud_data WHERE url = ?", url)
        .execute(pool)
        .await?;

    Ok(del_count.rows_affected())
}

pub async fn get_mud_from_url(url: String, pool: &DbConnection) -> Result<MudData> {
    // lookup datenbank ob schon existiert und nicht abgelaufen
    let existing_mud = get_mud(&url, pool).await;

    if let Some(mud) = existing_mud {
        if mud.expiration > Local::now().naive_local() {
            if let Ok(mud) = serde_json::from_str::<MudData>(mud.data.as_str()) {
                return Ok(mud);
            }
        }
    }

    // wenn nicht: fetch
    let mud_json = fetch_mud(url.as_str()).await?;

    // ruf parse_mud auf
    let data = parser::parse_mud(url.clone(), mud_json.as_str())?;

    // speichern in db
    let mud = MudDbo {
        url: url.clone(),
        data: serde_json::to_string(&data)?,
        acl_override: None,
        created_at: Local::now().naive_local(),
        expiration: data.expiration.naive_local(),
    };

    debug!("new/updating mud profile: {:?}", mud);

    upsert_mud(&mud, pool).await?;

    // return muddata
    Ok(data)
}

async fn fetch_mud(url: &str) -> Result<String> {
    Ok(isahc::get_async(url).await?.text().await?)
}

pub fn is_url(url: &str) -> bool {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"https?://(-\.)?([^\s/?\.#-]+\.?)+(/[^\s]*)?$").unwrap();
    }
    RE.is_match(url)
}

pub fn generate_empty_custom_mud_profile(url: &str, acl_override: Option<Vec<Acl>>) -> MudData {
    MudData {
        url: url.to_string(),
        masa_url: None,
        last_update: Local::now().naive_local().to_string(),
        systeminfo: None,
        mfg_name: None,
        model_name: None,
        documentation: None,
        expiration: get_custom_mud_expiration(),
        acllist: vec![],
        acl_override,
    }
}

pub fn get_custom_mud_expiration() -> DateTime<Utc> {
    chrono::Utc.from_utc_datetime(&NaiveDate::from_ymd(2060, 01, 31).and_hms(0, 0, 0))
}
