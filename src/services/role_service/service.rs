use std::io;

use strum::IntoEnumIterator;

use crate::{
    db::DbConnection,
    error::Result,
    models::RoleDbo,
    routes::dtos::{RoleDto, RoleUpdateDto},
    services::role_service::permission::Permission,
};

pub const ROLE_ID_ADMIN: i64 = 0;
pub const ROLE_ID_GUEST: i64 = 1;

pub async fn role_create(conn: &DbConnection, role: RoleUpdateDto) -> Result<RoleDto> {
    let permissions_vec = role.permissions.join(",");

    #[cfg(not(feature = "postgres"))]
    let result = sqlx::query!(
        "INSERT INTO roles (name, permissions) VALUES (?, ?)",
        role.name,
        permissions_vec,
    )
    .execute(conn)
    .await?
    .last_insert_rowid();

    #[cfg(feature = "postgres")]
    let result = sqlx::query!(
        "INSERT INTO roles (name, permissions) VALUES ($1, $2) RETURNING id",
        role.name,
        permissions_vec,
    )
    .fetch_one(conn)
    .await?
    .id;

    role_get(conn, result).await
}

pub async fn role_get(conn: &DbConnection, role_id: i64) -> Result<RoleDto> {
    let role_db = sqlx::query_as!(RoleDbo, "SELECT * FROM roles WHERE id = $1", role_id)
        .fetch_one(conn)
        .await?;

    Ok(RoleDto {
        id: role_db.id,
        name: role_db.name,
        permissions: role_db.permissions.split(',').map(ToString::to_string).collect(),
    })
}

pub async fn role_update(conn: &DbConnection, role_id: i64, updated_role: RoleUpdateDto) -> Result<bool> {
    let permissions_vec: String = updated_role.permissions.join(",");
    let result = sqlx::query!(
        "UPDATE roles SET name = $1, permissions = $2 WHERE id = $3",
        updated_role.name,
        permissions_vec,
        role_id,
    )
    .execute(conn)
    .await?;

    Ok(result.rows_affected() == 1)
}

pub async fn role_delete(conn: &DbConnection, role_id: i64) -> Result<bool> {
    let del_count = sqlx::query!("DELETE FROM roles WHERE id = $1", role_id)
        .execute(conn)
        .await?;

    Ok(del_count.rows_affected() == 1)
}

pub async fn roles_get_all(conn: &DbConnection) -> Result<Vec<RoleDto>> {
    let roles = sqlx::query_as!(RoleDbo, "SELECT * FROM roles").fetch_all(conn).await?;
    Ok(roles
        .into_iter()
        .map(|role_db| RoleDto {
            id: role_db.id,
            name: role_db.name,
            permissions: role_db.permissions.split(',').map(ToString::to_string).collect(),
        })
        .collect())
}

pub fn permissions_get_all() -> Result<Vec<String>> {
    Ok(Permission::iter().map(|p| p.to_string()).collect())
}

pub async fn add_role_to_user(conn: &DbConnection, user_id: i64, role_id: i64) -> Result<()> {
    sqlx::query!(
        "INSERT INTO users_roles (user_id, role_id) VALUES ($1, $2)",
        user_id,
        role_id,
    )
    .execute(conn)
    .await?;

    Ok(())
}

pub async fn role_delete_from_user(conn: &DbConnection, user_id: i64, role_id: i64) -> Result<()> {
    let role_db = sqlx::query_as!(RoleDbo, "SELECT * FROM roles WHERE id = $1", role_id,)
        .fetch_one(conn)
        .await?;

    sqlx::query!(
        "DELETE FROM users_roles WHERE user_id = $1 and role_id = $2",
        role_db.id,
        user_id
    )
    .execute(conn)
    .await?;

    Ok(())
}

pub fn validate_permission_name(permissions: &[String]) -> ::std::io::Result<()> {
    if permissions.iter().any(|name| name.contains(',')) {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Name must not contain a comma.",
        ))
    } else {
        Ok(())
    }
}
