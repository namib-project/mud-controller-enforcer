use crate::{db::DbConnection, error::Result, routes::dtos::StatusDto, services::user_service, VERSION};
use paperclip::actix::{api_v2_operation, web, web::Json};

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(get_status));
}

#[api_v2_operation(summary = "Retrieve the version and setup status of this controller")]
async fn get_status(pool: web::Data<DbConnection>) -> Result<Json<StatusDto>> {
    let has_any_users = user_service::has_any_users(pool.get_ref()).await?;

    Ok(Json(StatusDto {
        setup_required: !has_any_users,
        version: VERSION,
    }))
}
