#![allow(clippy::needless_pass_by_value)]

use paperclip::actix::{api_v2_operation, web, web::Json};

use crate::{db::ConnectionType, error::Result, routes::dtos::device_dto::DeviceDto, services::device_service};

#[api_v2_operation]
async fn get_all_devices(pool: web::Data<ConnectionType>) -> Result<Json<Vec<DeviceDto>>> {
    let res = device_service::get_all_devices(pool.get_ref()).await?;
    info!("{:?}", res);
    Ok(Json(res.into_iter().map(|d| DeviceDto::from(d)).collect()))
}

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("/", web::get().to(get_all_devices));
}
