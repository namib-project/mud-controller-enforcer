#![allow(clippy::needless_pass_by_value)]

use paperclip::actix::{api_v2_operation, web, web::Json};

use crate::{auth::Auth, db::DbConnection, error::Result, routes::dtos::DeviceDto, services::device_service};

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(get_all_devices));
}

#[api_v2_operation]
async fn get_all_devices(pool: web::Data<DbConnection>, auth: Auth) -> Result<Json<Vec<DeviceDto>>> {
    auth.require_permission("device/list")?;
    let res = device_service::get_all_devices(pool.get_ref()).await?;
    info!("{:?}", res);
    Ok(Json(res.into_iter().map(DeviceDto::from).collect()))
}
