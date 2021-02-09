#![allow(clippy::needless_pass_by_value)]

use crate::{
    auth::Auth,
    db::DbConnection,
    error::Result,
    models::{MudData, MudDbo},
    routes::dtos::{MudCreationDto, MudUpdateDto},
    services::{mud_service, mud_service::is_url},
};
use actix_web::HttpResponse;
use chrono::Utc;
use paperclip::actix::{api_v2_operation, web, web::Json};

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("/{url}", web::get().to(get_mud));
    cfg.route("/{url}", web::put().to(update_mud));
    cfg.route("/{url}", web::delete().to(delete_mud));
    cfg.route("/", web::post().to(create_mud));
}

#[api_v2_operation]
pub async fn get_mud(pool: web::Data<DbConnection>, auth: Auth, url: web::Path<String>) -> Result<Json<MudData>> {
    if url.into_inner().is_empty() {
        auth.require_permission("mud/list")?;
        auth.require_permission("mud/read")?;
        match mud_service::get_mud(&url.into_inner(), &pool).await {
            None => Err(actix_web::error::ErrorNotFound("Couldn't find MUD-Profile")),
            Some(mud_dbo) => Ok(Json(serde_json::from_str::<MudData>(mud_dbo.data.as_str())?)),
        }
    } else {
        auth.require_permission("mud/read")?;
        match mud_service::get_mud(&url.into_inner(), &pool).await {
            None => Err(actix_web::error::ErrorNotFound("Couldn't find MUD-Profile")),
            Some(mud_dbo) => Ok(Json(serde_json::from_str::<MudData>(mud_dbo.data.as_str())?)),
        }
    }
}

#[api_v2_operation]
pub async fn update_mud(
    pool: web::Data<DbConnection>,
    auth: Auth,
    url: web::Path<String>,
    mud_update_dto: Json<MudUpdateDto>,
) -> Result<Json<MudData>> {
    auth.require_permission("mud/write")?;

    let mut mud_dbo = match mud_service::get_mud(&url.into_inner(), &pool).await {
        None => return Err(actix_web::error::ErrorNotFound("MUD-Profile not found")),
        Some(mud_dbo) => mud_dbo,
    };

    let mut mud_data = serde_json::from_str::<MudData>(mud_dbo.data.as_str())?;
    mud_data.acl_override = mud_update_dto.acl_override.clone();

    mud_dbo.data = serde_json::to_string(&mud_data)?;

    mud_service::upsert_mud(&mud_dbo, &pool).await?;
    Ok(Json(mud_data))
}

#[api_v2_operation]
pub async fn delete_mud(pool: web::Data<DbConnection>, auth: Auth, url: web::Path<String>) -> Result<()> {
    auth.require_permission("mud/delete")?;

    if mud_service::get_mud(&url.into_inner(), &pool).await.is_none() {
        return Err(actix_web::error::ErrorNotFound("No MUD-Profile with this URL"));
    }

    if mud_service::delete_mud(&url.into_inner(), &pool).await? == 1 {
        Ok(HttpResponse::NoContent().finish())
    } else {
        Err(actix_web::error::ErrorInternalServerError(
            "Couldn't delete MUD, is it being used elsewhere?",
        ))
    }
}

#[api_v2_operation]
pub async fn create_mud(
    pool: web::Data<DbConnection>,
    auth: Auth,
    mud_creation_dto: Json<MudCreationDto>,
) -> Result<Json<MudData>> {
    auth.require_permission("mud/create")?;

    if mud_service::get_mud(&mud_creation_dto.mud_url, &pool).await.is_some() {
        return Err(actix_web::error::ErrorConflict("MUD-URL key already exists"));
    }

    // Check if the mud_url is actually an url. It might be a custom user mud-profile
    if is_url(&mud_creation_dto.mud_url) {
        let empty_mud = mud_service::generate_empty_custom_mud_profile(
            &mud_creation_dto.mud_url,
            mud_creation_dto.acl_override.clone(),
        );
        let mud_dbo = MudDbo {
            url: mud_creation_dto.mud_url.clone(),
            data: serde_json::to_string(&empty_mud)?,
            acl_override: match &mud_creation_dto.acl_override {
                Some(acls) => Some(serde_json::to_string(acls)?),
                None => None,
            },
            created_at: Utc::now().naive_local(),
            expiration: empty_mud.expiration.naive_local(),
        };

        mud_service::create_mud(&mud_dbo, &pool).await?;

        Ok(Json(empty_mud))
    } else {
        let created_mud = mud_service::get_mud_from_url(mud_creation_dto.mud_url.clone(), &pool).await?;

        Ok(Json(created_mud))
    }
}
