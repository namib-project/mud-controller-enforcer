use chrono::{Local, NaiveDateTime};
use diesel::{QueryDsl, QueryResult, RunQueryDsl};
use isahc::ResponseExt;

use crate::db::ConnectionType;
use crate::error::Result;
use crate::models::mud_models::{MUDData, MUD};
use crate::schema::mud_data;

mod json_models;
mod parser;

#[derive(Insertable)]
#[table_name = "mud_data"]
pub struct InsertableMUD {
    pub url: String,
    pub data: String,
    pub created_at: NaiveDateTime,
    pub expiration: NaiveDateTime,
}

pub async fn get_mud_from_url(url: String, conn: &ConnectionType) -> Result<MUDData> {
    // lookup datenbank ob schon existiert und nicht abgelaufen
    let existing_mud: QueryResult<MUD> = mud_data::table.find(&url).get_result::<MUD>(conn);
    if let Ok(mud) = existing_mud {
        if mud.expiration > Local::now().naive_local() {
            if let Ok(mud) = serde_json::from_str::<MUDData>(mud.data.as_str()) {
                return Ok(mud);
            }
        }
    }

    // wenn nicht: fetch
    let mud_json = fetch_mud(&url).await?;

    // ruf parse_mud auf
    let data = parser::parse_mud(url.clone(), mud_json)?;

    // speichern in db
    let mud = InsertableMUD {
        url: url.clone(),
        data: serde_json::to_string(&data)?,
        created_at: Local::now().naive_local(),
        expiration: data.expiration.naive_local(),
    };
    diesel::insert_into(mud_data::table)
        .values(mud)
        .execute(conn)?;

    // return muddata
    Ok(data)
}

async fn fetch_mud(url: &String) -> Result<String> {
    Ok(isahc::get_async(url).await?.text_async().await?)
}

pub async fn get_config_version() -> String {
    "test1".to_string()
}
