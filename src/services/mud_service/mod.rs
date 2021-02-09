use chrono::Local;
use isahc::AsyncReadResponseExt;
use lazy_static::lazy_static;
use regex::Regex;

use crate::{
    db::DbConnection,
    error::Result,
    models::{MudData, MudDbo},
};

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

pub async fn get_mud(url: &str, pool: &DbConnection) -> Option<MudDbo> {
    sqlx::query_as!(MudDbo, "SELECT * FROM mud_data WHERE url = ?", url)
        .fetch_optional(pool)
        .await
        .ok()?
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
