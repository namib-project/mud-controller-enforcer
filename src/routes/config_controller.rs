#![allow(clippy::needless_pass_by_value)]

use paperclip::actix::{api_v2_operation, web, web::Json};

use crate::{auth::Auth, db::DbConnection, error::Result, routes::dtos::ConfigQueryDto, services::config_service};
use std::collections::HashMap;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(get_configs));
    cfg.route("", web::patch().to(set_configs));
    cfg.route("", web::delete().to(delete_config));
}

#[api_v2_operation]
async fn get_configs(
    pool: web::Data<DbConnection>,
    auth: Auth,
    config_query_dto: web::Query<ConfigQueryDto>,
) -> Result<Json<HashMap<String, Option<String>>>> {
    auth.require_permission("config/read")?;

    let mut config_map: HashMap<String, Option<String>> = HashMap::new();

    for key in &config_query_dto.keys {
        config_map.insert(
            key.clone(),
            config_service::get_config_value(key.clone(), pool.as_ref()).await.ok(),
        );
    }

    info!("{:?}", config_map);
    Ok(Json(config_map))
}

#[api_v2_operation]
async fn set_configs(
    pool: web::Data<DbConnection>,
    auth: Auth,
    config_set_dto: Json<HashMap<String, String>>,
) -> Result<Json<HashMap<String, Option<String>>>> {
    auth.require_permission("config/write")?;

    for (key, value) in config_set_dto.0.clone() {
        config_service::set_config_value(key, value, pool.as_ref()).await?;
    }

    let keys = config_set_dto.0.keys().cloned().collect::<Vec<String>>();

    let mut config_map: HashMap<String, Option<String>> = HashMap::new();
    for key in keys {
        config_map.insert(
            key.clone(),
            config_service::get_config_value(key.clone(), pool.as_ref()).await.ok(),
        );
    }

    Ok(Json(config_map))
}

#[api_v2_operation]
async fn delete_config(
    pool: web::Data<DbConnection>,
    auth: Auth,
    config_delete_dto: Json<Vec<String>>,
) -> Result<Json<Vec<String>>> {
    auth.require_permission("config/delete")?;

    for key in &config_delete_dto.0 {
        config_service::delete_config_key(key.clone(), pool.as_ref()).await?
    }

    Ok(Json(config_delete_dto.0))
}
