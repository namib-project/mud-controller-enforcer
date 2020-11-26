#![allow(clippy::needless_pass_by_value)]

use rocket::{Route, State};
use rocket_contrib::json::Json;
use rocket_okapi::{openapi, routes_with_openapi};

use crate::{db::DbConnPool, error::Result, models::device_model::DeviceData, services::device_service};

#[openapi]
#[get("/")]
pub fn get_all_devices(pool: State<DbConnPool>) -> Result<Json<Vec<DeviceData>>> {
    let res = futures::executor::block_on(device_service::get_all_devices(pool.inner().clone()))?;
    info!("{:?}", res);
    Ok(Json(res))
}

pub fn routes() -> Vec<Route> {
    routes_with_openapi![get_all_devices]
}
