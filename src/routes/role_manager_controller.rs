#![allow(clippy::needless_pass_by_value)]

use crate::{db::DbConnection, error, error::Result, routes::dtos::RoleDto, services::role_service};
use actix_web::HttpResponse;
use isahc::http::StatusCode;
use paperclip::actix::{api_v2_operation, web, web::Json};
use validator::Validate;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("/", web::get().to(get_roles));
    cfg.route("/{id}", web::get().to(get_role));
    cfg.route("/", web::post().to(create_role));
    cfg.route("/{id}", web::put().to(edit_role));
    cfg.route("/{id}", web::delete().to(delete_role));
    cfg.route("/{id}/assign", web::post().to(assign_role));
}

#[api_v2_operation]
pub async fn get_roles(pool: web::Data<DbConnection>) -> Result<Json<Vec<RoleDto>>> {
    let res: Vec<RoleDto> = role_service::roles_get_all(pool.get_ref()).await?;
    info!("{:?}", res);
    Ok(Json(res))
}

#[api_v2_operation]
pub async fn get_role(pool: web::Data<DbConnection>, name: web::Path<String>) -> Result<Json<RoleDto>> {
    let res: RoleDto = role_service::role_get(pool.get_ref(), name.into_inner()).await?;
    info!("{:?}", res);
    Ok(Json(res))
}

#[api_v2_operation]
pub async fn create_role(
    pool: web::Data<DbConnection>,
    name: web::Path<String>,
    permissions: Json<Vec<String>>,
) -> Result<Json<RoleDto>> {
    let res: RoleDto = role_service::role_create(pool.get_ref(), name.into_inner(), permissions.into_inner()).await?;
    info!("{:?}", res);
    Ok(Json(res))
}

#[api_v2_operation]
pub async fn edit_role(
    pool: web::Data<DbConnection>,
    old_name: web::Path<String>,
    role_dto: Json<RoleDto>,
) -> Result<HttpResponse> {
    role_dto.validate().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let res = role_service::role_update(pool.get_ref(), old_name.into_inner(), role_dto.into_inner()).await?;
    info!("{:?}", res);
    Ok(HttpResponse::NoContent().finish())
}

#[api_v2_operation]
pub async fn delete_role(pool: web::Data<DbConnection>, name: web::Path<String>) -> Result<HttpResponse> {
    let res = role_service::role_delete(pool.get_ref(), name.into_inner()).await?;
    info!("{:?}", res);
    Ok(HttpResponse::NoContent().finish())
}

#[api_v2_operation]
pub async fn assign_role(
    pool: web::Data<DbConnection>,
    id: web::Path<i64>,
    name: web::Path<String>,
) -> Result<HttpResponse> {
    let res = role_service::role_add_to_user(pool.get_ref(), id.into_inner(), name.into_inner()).await?;
    info!("{:?}", res);
    Ok(HttpResponse::NoContent().finish())
}
