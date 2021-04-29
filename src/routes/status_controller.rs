use paperclip::actix::{api_v2_operation, web, web::Json};

use crate::{
    db::DbConnection,
    error::Result,
    routes::dtos::StatusDto,
    services::{acme_service, config_service, config_service::ConfigKeys, user_service},
    VERSION,
};

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(get_status));
}

#[api_v2_operation(summary = "Retrieve the version and setup status of this controller", tags(Status))]
async fn get_status(pool: web::Data<DbConnection>) -> Result<Json<StatusDto>> {
    let has_any_users = user_service::has_any_users(&pool).await?;
    let signup_allowed = config_service::get_config_value(ConfigKeys::AllowUserSignup.as_ref(), &pool).await?;
    let secure_name = acme_service::secure_name();

    Ok(Json(StatusDto {
        setup_required: !has_any_users,
        signup_allowed,
        version: VERSION,
        secure_name,
    }))
}
