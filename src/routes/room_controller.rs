#![allow(clippy::needless_pass_by_value)]

use paperclip::actix::{api_v2_operation, web, web::Json};

use crate::{
    auth::AuthToken,
    db::DbConnection,
    error::Result,
    routes::dtos::{DeviceDto, RoomDto},
    services::room_service,
};

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(get_all_rooms));
}

#[api_v2_operation]
async fn get_all_rooms(pool: web::Data<DbConnection>, auth: AuthToken) -> Result<Json<Vec<RoomDto>>> {
    auth.require_permission("room/list")?;
    let res = room_service::get_all_rooms(pool.get_ref()).await?;
    info!("{:?}", res);
    Ok(Json(res.into_iter().map(RoomDto::from).collect()))
}
