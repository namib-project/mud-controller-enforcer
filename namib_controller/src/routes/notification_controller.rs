// Copyright 2022, Matthias Reichmann
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::needless_pass_by_value)]

use futures::{stream, StreamExt, TryStreamExt};
use actix_web::http::StatusCode;
use paperclip::actix::{
    api_v2_operation, web,
    web::{Json},
};
use validator::Validate;

use crate::{
    auth::AuthToken,
    db::DbConnection,
    error,
    error::Result,
    routes::dtos::{NotificationDto, NotificationCreationDto},
    services::{notification_service, role_service::Permission},
};
use crate::models::Notification;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(get_all_notifications));
    cfg.route("", web::post().to(create_notification));
    cfg.route("/{id}", web::get().to(get_notification));
    cfg.route("/{id}", web::put().to(mark_as_read));
    cfg.route("/{id}", web::delete().to(delete_notification));
}

#[api_v2_operation(summary = "Return all notifications.", tags(Notifications))]
async fn get_all_notifications(pool: web::Data<DbConnection>, auth: AuthToken) -> Result<Json<Vec<NotificationDto>>> {
    auth.require_permission(Permission::notification__list)?;
    auth.require_permission(Permission::notification__read)?;

    let notifications = notification_service::get_all_notifications(&pool).await?;
    Ok(Json(
        stream::iter(notifications)
            .then(|n| n.load_refs(&pool))
            .map_ok(NotificationDto::from)
            .try_collect()
            .await?,
    ))
}

#[api_v2_operation(summary = "Get a notification through the notification id.", tags(Notifications))]
async fn get_notification(pool: web::Data<DbConnection>, auth: AuthToken, id: web::Path<i64>) -> Result<Json<NotificationDto>> {
    auth.require_permission(Permission::notification__read)?;

    let notification = find_notification(id.into_inner(), &pool).await?;

    Ok(Json(NotificationDto::from(notification.load_refs(&pool).await?)))
}

#[api_v2_operation(summary = "Creates a new notification.", tags(Notifications))]
async fn create_notification(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    notification_creation_update_dto: Json<NotificationCreationDto>,
) -> Result<Json<NotificationDto>> {
    auth.require_permission(Permission::notification__write)?;

    notification_creation_update_dto.validate().or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: None,
        }
        .fail()
    })?;

    let notification = notification_creation_update_dto.into_inner().into_notification();
    let id = notification_service::insert_notification(&notification, &pool).await?;

    let created_notification = find_notification(id, &pool).await?;
    Ok(Json(NotificationDto::from(created_notification.load_refs(&pool).await?)))
}

#[api_v2_operation(summary = "Marks the notification as read.", tags(Notifications))]
async fn mark_as_read(pool: web::Data<DbConnection>, auth: AuthToken, id: web::Path<i64>, ) -> Result<Json<NotificationDto>> {
    auth.require_permission(Permission::notification__write)?;

    let notification = find_notification(id.0, &pool).await?;

    notification_service::mark_as_read(&notification, &pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::BAD_REQUEST,
            message: Some("Could not update notification.".to_string()),
        }
        .fail()
    })?;

    let notification_with_refs = notification.load_refs(&pool).await?;
    Ok(Json(NotificationDto::from(notification_with_refs)))
}

#[api_v2_operation(summary = "Deletes a notification.", tags(Notifications))]
async fn delete_notification(pool: web::Data<DbConnection>, auth: AuthToken, id: web::Path<i64>) -> Result<Json<NotificationDto>> {
    auth.require_permission(Permission::notification__delete)?;

    let notification = find_notification(id.0, &pool).await?;
    notification_service::delete_notification(&notification, &pool).await?;

    let notification_with_refs = notification.load_refs(&pool).await?;
    Ok(Json(NotificationDto::from(notification_with_refs)))
}

/// Helper method for finding a notification with a given id, or returning a 404 error if not found.
async fn find_notification(id: i64, pool: &DbConnection) -> Result<Notification> {
    notification_service::find_by_id(id, pool).await.or_else(|_| {
        error::ResponseError {
            status: StatusCode::NOT_FOUND,
            message: Some("No notification with this id found".to_string()),
        }
            .fail()
    })
}
