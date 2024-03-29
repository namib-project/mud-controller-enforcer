// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use actix_web::web::Json;
use paperclip::actix::{api_v2_operation, web};

use crate::{
    auth::AuthToken,
    db::DbConnection,
    error::Result,
    routes::dtos::{EnforcerDto, EnforcerUpdateQuery},
    services::{enforcer_service, role_service::Permission},
};

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(get_enforcers));
    cfg.route("/{cert_id}", web::get().to(get_enforcer));
    cfg.route("/{cert_id}", web::put().to(update_enforcer));
}

#[api_v2_operation(summary = "Retrieve a list of the connected enforcers", tags(Enforcers))]
async fn get_enforcers(pool: web::Data<DbConnection>, auth: AuthToken) -> Result<Json<Vec<EnforcerDto>>> {
    auth.require_permission(Permission::enforcer__read)?;
    auth.require_permission(Permission::enforcer__list)?;
    let enforcers = enforcer_service::get_enforcers(&pool).await?;
    Ok(Json(enforcers))
}

#[api_v2_operation(summary = "Retrieve a single enforcer", tags(Enforcers))]
async fn get_enforcer(
    cert_id: web::Path<String>,
    pool: web::Data<DbConnection>,
    auth: AuthToken,
) -> Result<Json<EnforcerDto>> {
    auth.require_permission(Permission::enforcer__read)?;
    let enforcer = enforcer_service::get_enforcer(&cert_id, &pool).await?;
    Ok(Json(enforcer))
}

#[api_v2_operation(summary = "Allow or forbid a enforcer from connecting", tags(Enforcers))]
async fn update_enforcer(
    cert_id: web::Path<String>,
    query: web::Query<EnforcerUpdateQuery>,
    auth: AuthToken,
    pool: web::Data<DbConnection>,
) -> Result<Json<EnforcerDto>> {
    auth.require_permission(Permission::enforcer__update)?;
    let result = enforcer_service::set_enforcer_allowed(&cert_id, query.allowed, &pool).await?;
    Ok(Json(result))
}
