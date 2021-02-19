#![allow(clippy::needless_pass_by_value)]

use paperclip::actix::{api_v2_operation, web, web::Json};

use crate::{auth::AuthToken, db::DbConnection, error::Result, routes::dtos::ConfigQueryDto, services::config_service};
use std::collections::HashMap;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(get_configs));
    cfg.route("", web::patch().to(set_configs));
    cfg.route("", web::delete().to(delete_config));
}

#[api_v2_operation]
async fn get_configs(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    config_query_dto: web::Query<ConfigQueryDto>,
) -> Result<Json<HashMap<String, Option<String>>>> {
    auth.require_permission("config/read")?;

    let mut config_map: HashMap<String, Option<String>> = HashMap::new();

    if config_query_dto.keys.is_empty() {
        auth.require_permission("config/list")?;
        let data = config_service::get_all_config_data(&pool).await?;
        for config in data {
            config_map.insert(config.key, Some(config.value));
        }
    } else {
        for key in &config_query_dto.keys {
            config_map.insert(key.clone(), config_service::get_config_value(key, &pool).await.ok());
        }
    }

    info!("{:?}", config_map);
    Ok(Json(config_map))
}

#[api_v2_operation]
async fn set_configs(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    config_set_dto: Json<HashMap<String, String>>,
) -> Result<Json<HashMap<String, Option<String>>>> {
    auth.require_permission("config/write")?;

    for (key, value) in &config_set_dto.0 {
        config_service::set_config_value(&key, value, &pool).await?;
    }

    let keyrefs = config_set_dto.0.keys().collect::<Vec<&String>>();

    let mut config_map: HashMap<String, Option<String>> = HashMap::new();
    for key in keyrefs {
        config_map.insert((*key).clone(), config_service::get_config_value(key, &pool).await.ok());
    }

    Ok(Json(config_map))
}

#[api_v2_operation]
async fn delete_config(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    config_delete_dto: Json<Vec<String>>,
) -> Result<Json<HashMap<String, bool>>> {
    auth.require_permission("config/delete")?;

    let mut deletion_map: HashMap<String, bool> = HashMap::new();
    for key in &config_delete_dto.0 {
        deletion_map.insert(key.clone(), config_service::delete_config_key(key, &pool).await? != 0);
    }

    Ok(Json(deletion_map))
}
