use chrono::Local;
use isahc::AsyncReadResponseExt;

use crate::{
    db::ConnectionType,
    error::Result,
    models::{MudData, MudDbo},
};

mod json_models;
mod parser;

pub async fn get_mud_from_url(url: String, pool: &ConnectionType) -> Result<MudData> {
    // lookup datenbank ob schon existiert und nicht abgelaufen
    let existing_mud: Option<MudDbo> = sqlx::query_as!(MudDbo, "select * from mud_data where url = ?", url)
        .fetch_optional(pool)
        .await?;
    let mut exists = false;
    if let Some(mud) = existing_mud {
        if mud.expiration > Local::now().naive_local() {
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
        created_at: Local::now().naive_local(),
        expiration: data.expiration.naive_local(),
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
