// Copyright 2022, Hannes Masuch
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::needless_pass_by_value)]

use futures::{stream, StreamExt, TryStreamExt};
use paperclip::actix::{api_v2_operation, web, web::Json};

use crate::{
    auth::AuthToken,
    db::DbConnection,
    error::Result,
    routes::device_controller,
    routes::dtos::DeviceDto,
    services::{device_service, role_service::Permission},
};

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(get_all_quarantined_devices));
    cfg.route("/{id}", web::put().to(quarantine_device));
    cfg.route("/{id}", web::delete().to(remove_device_from_quarantine));
}

#[api_v2_operation(summary = "List all quarantined devices", tags(Devices))]
async fn get_all_quarantined_devices(pool: web::Data<DbConnection>, auth: AuthToken) -> Result<Json<Vec<DeviceDto>>> {
    auth.require_permission(Permission::device__list)?;
    auth.require_permission(Permission::device__read)?;

    let devices = device_service::get_all_quarantined_devices(&pool).await?;
    Ok(Json(
        stream::iter(devices)
            .then(|d| d.load_refs(&pool))
            .map_ok(DeviceDto::from)
            .try_collect()
            .await?,
    ))
}

#[api_v2_operation(summary = "Quarantine device")]
async fn quarantine_device(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    id: web::Path<i64>,
) -> Result<Json<DeviceDto>> {
    auth.require_permission(Permission::device__write)?;

    let mut device_with_refs = device_controller::find_device(id.into_inner(), &pool).await?;

    device_service::change_quarantine_status_device(device_with_refs.id, &pool, true).await?;

    device_with_refs.q_bit = true;

    Ok(Json(DeviceDto::from(device_with_refs.load_refs(&pool).await?)))
}

#[api_v2_operation(summary = "Remove device from quarantine")]
async fn remove_device_from_quarantine(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    id: web::Path<i64>,
) -> Result<Json<DeviceDto>> {
    auth.require_permission(Permission::device__write)?;

    let mut device_with_refs = device_controller::find_device(id.into_inner(), &pool).await?;

    device_service::change_quarantine_status_device(device_with_refs.id, &pool, false).await?;

    device_with_refs.q_bit = false;

    Ok(Json(DeviceDto::from(device_with_refs.load_refs(&pool).await?)))
}
