#![allow(clippy::needless_pass_by_value)]

use crate::{
    auth::AuthToken,
    db::DbConnection,
    error,
    error::Result,
    routes::dtos::{RoleAssignDto, RoleDto, RoleUpdateDto},
    services::role_service::{self, Permission},
};
use actix_web::{http::StatusCode, HttpResponse};
use paperclip::actix::{api_v2_operation, web, web::Json};
use validator::Validate;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("/", web::get().to(get_roles));
    cfg.route("/", web::post().to(create_role));
    cfg.route("/available-permissions", web::get().to(available_permissions));
    cfg.route("/assign", web::post().to(assign_role));
    cfg.route("/unassign", web::post().to(unassign_role));
    cfg.route("/{role_id}", web::get().to(get_role));
    cfg.route("/{role_id}", web::put().to(edit_role));
    cfg.route("/{role_id}", web::delete().to(delete_role));
}

#[api_v2_operation(summary = "List of all roles")]
pub async fn get_roles(pool: web::Data<DbConnection>, auth: AuthToken) -> Result<Json<Vec<RoleDto>>> {
    auth.require_permission(Permission::role__list)?;
    let res: Vec<RoleDto> = role_service::roles_get_all(&pool).await?;
    Ok(Json(res))
}

#[api_v2_operation(summary = "Get a specific role")]
pub async fn get_role(
    pool: web::Data<DbConnection>,
    role_id: web::Path<i64>,
    auth: AuthToken,
) -> Result<Json<RoleDto>> {
    auth.require_permission(Permission::role__read)?;
    let res: RoleDto = role_service::role_get(&pool, role_id.into_inner()).await?;
    Ok(Json(res))
}

#[api_v2_operation(summary = "Create a new role")]
pub async fn create_role(
    pool: web::Data<DbConnection>,
    role_dto: Json<RoleUpdateDto>,
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

    role_service::validate_permission_name(&role_dto.permissions).or_else(|e| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: e.to_string(),
        }
        .fail()
    })?;

    let res: RoleDto = role_service::role_create(&pool, role_dto.into_inner()).await?;
    Ok(Json(res))
}

#[api_v2_operation(summary = "Edit a specific role")]
pub async fn edit_role(
    pool: web::Data<DbConnection>,
    role_id: web::Path<i64>,
    role_dto: Json<RoleUpdateDto>,
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

    let role_id = role_id.into_inner();

    role_service::role_get(&pool, role_id).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: "Role not found".to_string(),
        }
        .fail()
    })?;

    role_service::validate_permission_name(&role_dto.permissions).or_else(|e| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: e.to_string(),
        }
        .fail()
    })?;

    if role_service::role_update(&pool, role_id, role_dto.into_inner()).await? {
        Ok(HttpResponse::NoContent().finish())
    } else {
        // return 404 if no role was updated
        Ok(HttpResponse::NotFound().finish())
    }
}

#[api_v2_operation(summary = "Delete a role")]
pub async fn delete_role(
    pool: web::Data<DbConnection>,
    role_id: web::Path<i64>,
    auth: AuthToken,
) -> Result<HttpResponse> {
    auth.require_permission(Permission::role__delete)?;
    role_service::role_delete(&pool, role_id.into_inner()).await?;
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
    role_service::add_role_to_user(&pool, assignment.user_id, assignment.role_id).await?;
    Ok(HttpResponse::NoContent().finish())
}

#[api_v2_operation(summary = "Unassign a specific role from an user")]
pub async fn unassign_role(
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
    role_service::role_delete_from_user(&pool, assignment.user_id, assignment.role_id).await?;
    Ok(HttpResponse::NoContent().finish())
}

#[api_v2_operation(summary = "List of all available permissions")]
pub async fn available_permissions(_: AuthToken) -> Result<Json<Vec<String>>> {
    let permissions: Vec<String> = role_service::permissions_get_all().unwrap();
    Ok(Json(permissions))
}
