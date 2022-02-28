// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use url::Url;

use crate::{
    db::DbConnection,
    error,
    error::Result,
    models::{Acl, MudData, MudDbo, MudDboRefresh},
    services::{firewall_configuration_service::update_config_version, mud_service::fetch::fetch_mud},
};

mod fetch;
pub mod json_models;
pub mod parser;

/// Writes the `MudDbo` to the database.
/// Upserts data by `MudDbo::url`
pub async fn upsert_mud(mud_profile: &MudDbo, pool: &DbConnection) -> Result<()> {
    sqlx::query!(
        "INSERT INTO mud_data (url, data, created_at, expiration) VALUES ($1, $2, $3, $4) ON CONFLICT(url) DO UPDATE SET data = excluded.data, created_at = excluded.created_at, expiration = excluded.expiration",
        mud_profile.url,
        mud_profile.data,
        mud_profile.created_at,
        mud_profile.expiration,
    )
        .execute(pool)
        .await?;

    Ok(())
}

/// Creates MUD Profile using `MudDbo` Data
pub async fn create_mud(mud_profile: &MudDbo, pool: &DbConnection) -> Result<()> {
    let _ins_count = sqlx::query!(
        "INSERT INTO mud_data (url, data, created_at, expiration) VALUES ($1, $2, $3, $4)",
        mud_profile.url,
        mud_profile.data,
        mud_profile.created_at,
        mud_profile.expiration,
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Returns the MUD-Profile if it exists
pub async fn get_mud(url: &str, pool: &DbConnection) -> Option<MudDbo> {
    sqlx::query_as!(MudDbo, "SELECT * FROM mud_data WHERE url = $1", url)
        .fetch_optional(pool)
        .await
        .ok()?
}

/// Returns all existing MUD-Profiles
pub async fn get_all_muds(pool: &DbConnection) -> Result<Vec<MudDbo>> {
    let data = sqlx::query_as!(MudDbo, "SELECT * FROM mud_data")
        .fetch_all(pool)
        .await?;

    Ok(data)
}

/// Deletes a MUD-Profile using the MUD-URL/-Name
pub async fn delete_mud(url: &str, pool: &DbConnection) -> Result<bool> {
    let del_count = sqlx::query!("DELETE FROM mud_data WHERE url = $1", url)
        .execute(pool)
        .await?;

    Ok(del_count.rows_affected() == 1)
}

/// Checks if a Device is using the MUD-Profile
pub async fn is_mud_used(url: &str, pool: &DbConnection) -> Result<bool> {
    let device_using_mud = sqlx::query!("SELECT * FROM devices WHERE mud_url = $1", url)
        .fetch_optional(pool)
        .await?;

    Ok(device_using_mud.is_some())
}

/// This function return `MudDboRefresh` they only containing url and expiration
/// to reduce payload.
async fn get_all_mud_expiration(pool: &DbConnection) -> Result<Vec<MudDboRefresh>> {
    Ok(sqlx::query_as!(MudDboRefresh, "SELECT url, expiration FROM mud_data")
        .fetch_all(pool)
        .await?)
}

/// Returns a MUD-Profile Data using the MUD-URL
/// Creates the MUD-Profile if it doesn't exist
/// If it exists, uses existing data from DB
/// This function is mainly used in the `RPCServer`, where it's used to save Device's MUD-URLs which are being sent via DHCP
/// Local MUD-Profiles can be loaded *BUT NOT CREATED* through this function, since they have an expiration far far in the future
pub async fn get_or_fetch_mud(url: &str, pool: &DbConnection) -> Result<MudData> {
    let mut expired_mud_data: Option<MudData> = None;

    // lookup datenbank ob schon existiert und nicht abgelaufen
    if let Some(mud) = get_mud(url, pool).await {
        if let Ok(mud_data) = mud.parse_data() {
            if mud.expiration > Utc::now().naive_utc() {
                return Ok(mud_data);
            }
            expired_mud_data = Some(mud_data);
        }
    }

    // mud_url muss ein https:// url sein.
    if !is_url(url) || !url.starts_with("https://") {
        error::MudFileInvalid {}.fail()?;
    }

    // wenn nicht: fetch
    // falls ein fehler auftritt verwende die alte mud_data
    let mud_json = match fetch_mud(url).await {
        Ok(m) => m,
        Err(e) => return expired_mud_data.ok_or(e),
    };

    // ruf parse_mud auf
    // falls ein fehler auftritt verwende die alte mud_data
    let mut data = match parser::parse_mud(url.to_string(), mud_json.as_str()) {
        Ok(d) => d,
        Err(e) => return expired_mud_data.ok_or(e),
    };
    // acl_override von alter mud_data übernehmen
    if let Some(MudData { acl_override, .. }) = expired_mud_data {
        data.acl_override = acl_override;
    }

    // speichern in db
    let mud = MudDbo {
        url: url.to_string(),
        data: serde_json::to_string(&data)?,
        created_at: Utc::now().naive_utc(),
        expiration: data.expiration.naive_utc(),
    };

    debug!("new/updating mud profile: {:?}", mud);

    upsert_mud(&mud, pool).await?;

    // return muddata
    Ok(data)
}

/// Checks if the given string is an URL. Used to check if the MUD-Profile being created is local or needs to be fetched.
pub fn is_url(url: &str) -> bool {
    Url::parse(url).is_ok()
}

/// Generates an empty MUD-Profile for custom local usage
pub fn generate_empty_custom_mud_profile(url: &str, acl_override: Vec<Acl>) -> MudData {
    MudData {
        url: url.to_string(),
        masa_url: None,
        last_update: Utc::now().naive_utc().to_string(),
        systeminfo: None,
        mfg_name: None,
        model_name: None,
        documentation: None,
        expiration: get_custom_mud_expiration(),
        acllist: vec![],
        acl_override,
    }
}

/// Generates an expiration date, which is far in the future. Mainly used for custom local MUD-Profiles
pub fn get_custom_mud_expiration() -> DateTime<Utc> {
    Utc.from_utc_datetime(&NaiveDate::from_ymd(2060, 1, 31).and_hms(0, 0, 0))
}

pub async fn update_outdated_profiles(db_pool: &DbConnection) -> Result<()> {
    debug!("Update outdated profiles");
    let mud_data = get_all_mud_expiration(db_pool).await?;
    let mud_vec: Vec<String> = mud_data
        .into_iter()
        .filter(|mud| mud.expiration < Utc::now().naive_utc())
        .map(|mud| mud.url)
        .collect();
    if mud_vec.is_empty() {
        return Ok(());
    }
    update_mud_urls(mud_vec, db_pool).await?;
    update_config_version(db_pool).await
}

async fn update_mud_urls(vec_url: Vec<String>, db_pool: &DbConnection) -> Result<()> {
    for mud_url in vec_url {
        debug!("Try to update url: {}", mud_url);
        let updated_mud = get_or_fetch_mud(&mud_url, db_pool).await?;
        debug!("Updated mud profile: {:#?}", updated_mud);
    }
    Ok(())
}
