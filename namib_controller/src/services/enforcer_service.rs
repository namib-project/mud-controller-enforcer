// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::net::IpAddr;

use chrono::Utc;
use snafu::ensure;

use crate::{db::DbConnection, error, error::Result, routes::dtos::EnforcerDto, services::acme_service::CertId};

/// Register an incoming enforcer, failing if it has not been accepted yet.
pub async fn register_enforcer(conn: &DbConnection, ip_addr: IpAddr, cert_id: &CertId) -> Result<()> {
    let last_interaction = Utc::now().naive_utc();
    let cert_id_str = cert_id.to_string();
    let ip_addr_str = ip_addr.to_string();
    let result = sqlx::query!("SELECT allowed FROM enforcers WHERE cert_id = $1", cert_id_str)
        .fetch_optional(conn)
        .await?;
    if let Some(enforcer) = result {
        sqlx::query!(
            "UPDATE enforcers SET last_interaction = $1, last_ip_address = $2 WHERE cert_id = $3",
            last_interaction,
            ip_addr_str,
            cert_id_str
        )
        .execute(conn)
        .await?;
        ensure!(enforcer.allowed, error::EnforcerNotAllowed {});
        Ok(())
    } else {
        sqlx::query!(
            "INSERT INTO enforcers (cert_id, last_ip_address, last_interaction, allowed) VALUES ($1, $2, $3, $4)",
            cert_id_str,
            ip_addr_str,
            last_interaction,
            false
        )
        .execute(conn)
        .await?;
        error::EnforcerNotAllowed {}.fail()
    }
}

pub async fn get_enforcers(conn: &DbConnection) -> Result<Vec<EnforcerDto>> {
    let result = sqlx::query_as!(EnforcerDto, "SELECT * FROM enforcers")
        .fetch_all(conn)
        .await?;
    Ok(result)
}

pub async fn get_enforcer(cert_id: &str, conn: &DbConnection) -> Result<EnforcerDto> {
    let result = sqlx::query_as!(EnforcerDto, "SELECT * FROM enforcers WHERE cert_id = $1", cert_id)
        .fetch_one(conn)
        .await?;
    Ok(result)
}

pub async fn set_enforcer_allowed(cert_id: &str, allowed: bool, conn: &DbConnection) -> Result<EnforcerDto> {
    sqlx::query!("UPDATE enforcers SET allowed = $1 WHERE cert_id = $2", allowed, cert_id)
        .execute(conn)
        .await?;
    let result = sqlx::query_as!(EnforcerDto, "SELECT * FROM enforcers WHERE cert_id = $1", cert_id)
        .fetch_one(conn)
        .await?;
    Ok(result)
}
