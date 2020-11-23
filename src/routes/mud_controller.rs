#![allow(clippy::needless_pass_by_value)]

use rocket::Route;
use rocket_contrib::json::Json;
use rocket_okapi::{openapi, routes_with_openapi};

use crate::{db::DbConn, error::Result, models::mud_models::MUDData, services::mud_service};

#[openapi]
#[get("/?<url>")]
pub fn get_mud(conn: DbConn, url: String) -> Result<Json<MUDData>> {
    let res = futures::executor::block_on(mud_service::get_mud_from_url(url, &*conn))?;
    info!("{:?}", res);
    Ok(Json(res))
}

pub fn routes() -> Vec<Route> {
    routes_with_openapi![get_mud]
}
