use crate::db::DbConn;
use crate::error::*;
use crate::models::mud_models::MUDData;
use crate::services::mud_service;
use futures::Future;
use rocket::Route;
use rocket_contrib::json::Json;
use rocket_contrib::json::JsonValue;
use rocket_okapi::{openapi, routes_with_openapi};
use serde_json::json;
use tokio::runtime::Runtime;

#[openapi]
#[get("/?<url>")]
pub fn get_mud(conn: DbConn, url: String) -> Result<Json<MUDData>> {
    let res = futures::executor::block_on(mud_service::get_mud_from_url(url, &*conn))?;
    info!("{:?}", res);
    // let res = futures::executor::block_on(mud_service::get_mud_from_url(url, &*conn))?;
    Ok(Json(res))
}

pub fn routes() -> Vec<Route> {
    routes_with_openapi![get_mud]
}
