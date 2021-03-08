#![allow(clippy::needless_pass_by_value)]

use crate::{
    auth::AuthToken,
    db::DbConnection,
    error,
    error::Result,
    routes::dtos::{RoleAssignDto, RoleDto},
    services::role_service::{permission::Permission, role_service},
};
use actix_web::HttpResponse;
use isahc::http::StatusCode;
use paperclip::actix::{api_v2_operation, web, web::Json};
use validator::Validate;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("/", web::get().to(get_roles));
    cfg.route("/", web::post().to(create_role));
    cfg.route("/available-permissions", web::get().to(available_permissions));
    cfg.route("/assign", web::post().to(assign_role));
    cfg.route("/{name}", web::get().to(get_role));
    cfg.route("/{name}", web::put().to(edit_role));
    cfg.route("/{name}", web::delete().to(delete_role));
}

#[api_v2_operation(summary = "List of all roles")]
pub async fn get_roles(pool: web::Data<DbConnection>, _: AuthToken) -> Result<Json<Vec<RoleDto>>> {
    let res: Vec<RoleDto> = role_service::roles_get_all(pool.get_ref()).await?;
    Ok(Json(res))
}

#[api_v2_operation(summary = "Get a specific role")]
pub async fn get_role(
    pool: web::Data<DbConnection>,
    name: web::Path<String>,
    auth: AuthToken,
) -> Result<Json<RoleDto>> {
    auth.require_permission(Permission::role__list)?;
    let res: RoleDto = role_service::role_get(pool.get_ref(), name.into_inner()).await?;
    Ok(Json(res))
}

#[api_v2_operation(summary = "Create a new role")]
pub async fn create_role(
    pool: web::Data<DbConnection>,
    role_dto: Json<RoleDto>,
    auth: AuthToken,
) -> Result<Json<RoleDto>> {
    auth.require_permission(Permission::role__write)?;
    role_dto.validate().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let res: RoleDto = role_service::role_create(pool.get_ref(), role_dto.into_inner()).await?;
    Ok(Json(res))
}

#[api_v2_operation(summary = "Edit a specific role")]
pub async fn edit_role(
    pool: web::Data<DbConnection>,
    old_name: web::Path<String>,
    role_dto: Json<RoleDto>,
    auth: AuthToken,
) -> Result<HttpResponse> {
    auth.require_permission(Permission::role__write)?;
    role_dto.validate().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let old_name_str: String = old_name.into_inner();

    role_service::role_get(pool.get_ref(), old_name_str.clone())
        .await
        .or_else(|_| {
            error::ResponseError {
                status: StatusCode::NOT_FOUND,
                message: None,
            }
            .fail()
        })?;

    let res = role_service::role_update(pool.get_ref(), old_name_str, role_dto.into_inner()).await?;
    Ok(HttpResponse::NoContent().finish())
}

#[api_v2_operation(summary = "Delete a role")]
pub async fn delete_role(
    pool: web::Data<DbConnection>,
    name: web::Path<String>,
    auth: AuthToken,
) -> Result<HttpResponse> {
    auth.require_permission(Permission::role__delete)?;
    let res = role_service::role_delete(pool.get_ref(), name.into_inner()).await?;
    Ok(HttpResponse::NoContent().finish())
}

#[api_v2_operation(summary = "Assign a specific role to an user")]
pub async fn assign_role(
    pool: web::Data<DbConnection>,
    assignment_dto: Json<RoleAssignDto>,
    auth: AuthToken,
) -> Result<HttpResponse> {
    auth.require_permission(Permission::role__assign)?;
    assignment_dto.validate().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let assignment: RoleAssignDto = assignment_dto.into_inner();
    let res = role_service::role_add_to_user(pool.get_ref(), assignment.id, assignment.name).await?;
    Ok(HttpResponse::NoContent().finish())
}

#[api_v2_operation(summary = "List of all available permissions")]
pub async fn available_permissions(_: AuthToken) -> Result<Json<Vec<String>>> {
    let permissions: Vec<String> = role_service::permissions_get_all().unwrap();
    Ok(Json(permissions))
}
