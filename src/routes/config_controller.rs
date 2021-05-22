// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::needless_pass_by_value)]

use std::collections::HashMap;

use paperclip::actix::{api_v2_operation, web, web::Json};

use crate::{
    auth::AuthToken,
    db::DbConnection,
    error::Result,
    routes::dtos::ConfigQueryDto,
    services::{config_service, role_service::Permission},
};

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(get_configs));
    cfg.route("", web::patch().to(set_configs));
    cfg.route("", web::delete().to(delete_config));
}

#[api_v2_operation(summary = "Retrieve all or a subset of system config key-value pairs", tags(Config))]
async fn get_configs(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    config_query_dto: web::Query<ConfigQueryDto>,
) -> Result<Json<HashMap<String, Option<String>>>> {
    auth.require_permission(Permission::config__read)?;

    let mut config_map: HashMap<String, Option<String>> = HashMap::new();

    if config_query_dto.keys.is_empty() {
        auth.require_permission(Permission::config__list)?;
        let data = config_service::get_all_config_data(&pool).await?;
        for config in data {
            config_map.insert(config.key, Some(config.value));
        }
    } else {
        for key in config_query_dto.into_inner().keys {
            let value = config_service::get_config_value(&key, &pool).await.ok();
            config_map.insert(key, value);
        }
    }

    info!("{:?}", config_map);
    Ok(Json(config_map))
}

#[api_v2_operation(summary = "Set system config values", tags(Config))]
async fn set_configs(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    config_set_dto: Json<HashMap<String, String>>,
) -> Result<Json<HashMap<String, Option<String>>>> {
    auth.require_permission(Permission::config__write)?;

    for (key, value) in config_set_dto.iter() {
        config_service::set_config_value(&key, value, &pool).await?;
    }

    let mut config_map: HashMap<String, Option<String>> = HashMap::new();
    for (key, _) in config_set_dto.into_inner() {
        let value = config_service::get_config_value(&key, &pool).await.ok();
        config_map.insert(key, value);
    }

    Ok(Json(config_map))
}

#[api_v2_operation(summary = "Delete the given system config entries", tags(Config))]
async fn delete_config(
    pool: web::Data<DbConnection>,
    auth: AuthToken,
    config_delete_dto: Json<Vec<String>>,
) -> Result<Json<HashMap<String, bool>>> {
    auth.require_permission(Permission::config__delete)?;

    let mut deletion_map: HashMap<String, bool> = HashMap::new();
    for key in config_delete_dto.into_inner() {
        let value = config_service::delete_config_key(&key, &pool).await?;
        deletion_map.insert(key, value);
    }

    Ok(Json(deletion_map))
}
