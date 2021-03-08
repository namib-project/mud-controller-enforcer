use crate::{
    db::DbConnection, error::Result, models::RoleDbo, routes::dtos::RoleDto,
    services::role_service::permission::Permission,
};
use sqlx::Done;
use std::iter::FromIterator;
use strum::IntoEnumIterator;

pub async fn role_create(conn: &DbConnection, role: RoleDto) -> Result<RoleDto> {
    let permissions_vec = role.permissions.join(",");
    let _ = sqlx::query!(
        "INSERT INTO roles (name, permissions) VALUES (?, ?)",
        role.name,
        permissions_vec,
    )
    .execute(conn)
    .await?;

    let new_role = sqlx::query_as!(RoleDbo, "SELECT * FROM roles WHERE name = ?", role.name,)
        .fetch_one(conn)
        .await?;

    let out_role = RoleDto {
        name: new_role.name,
        permissions: new_role.permissions.split(",").map(|s| s.to_string()).collect(),
    };

    Ok(out_role)
}

pub async fn role_get(conn: &DbConnection, name: String) -> Result<RoleDto> {
    let role_db = sqlx::query_as!(RoleDbo, "SELECT * FROM roles WHERE name = ?", name,)
        .fetch_one(conn)
        .await?;

    Ok(RoleDto {
        name: role_db.name,
        permissions: role_db.permissions.split(",").map(|s| s.to_string()).collect(),
    })
}

pub async fn role_update(conn: &DbConnection, old_name: String, updated_role: RoleDto) -> Result<()> {
    let permissions_vec: String = String::from_iter(updated_role.permissions);
    let _ = sqlx::query_as!(RoleDbo, "SELECT * FROM roles WHERE name=?", old_name)
        .fetch_one(conn)
        .await?;
    let _ = sqlx::query!(
        "UPDATE roles SET name=?, permissions=? WHERE name=?",
        updated_role.name,
        permissions_vec,
        old_name,
    )
    .execute(conn)
    .await?;

    Ok(())
}

pub async fn role_delete(conn: &DbConnection, name: String) -> Result<bool> {
    let del_count = sqlx::query!("DELETE FROM roles WHERE name = ?", name)
        .execute(conn)
        .await?;

    Ok(del_count.rows_affected() == 1)
}

pub async fn roles_get_all(conn: &DbConnection) -> Result<Vec<RoleDto>> {
    let roles = sqlx::query_as!(RoleDbo, "SELECT * FROM roles").fetch_all(conn).await?;
    Ok(roles
        .into_iter()
        .map(|role_db| RoleDto {
            name: role_db.name,
            permissions: role_db.permissions.split(",").map(|s| s.to_string()).collect(),
        })
        .collect())
}

pub fn permissions_get_all() -> Result<Vec<String>> {
    let mut permissions: Vec<String> = vec![];
    for permission in Permission::iter() {
        permissions.push(permission.to_string())
    }

    Ok(permissions)
}

pub async fn role_add_to_user(conn: &DbConnection, user_id: i64, name: String) -> Result<()> {
    let role_db = sqlx::query_as!(RoleDbo, "SELECT * FROM roles WHERE name = ?", name,)
        .fetch_one(conn)
        .await?;

    sqlx::query!(
        "INSERT INTO users_roles (user_id, role_id) VALUES (?, ?)",
        user_id,
        role_db.id,
    )
    .execute(conn)
    .await?;

    Ok(())
}

pub async fn role_delete_from_user(conn: &DbConnection, name: String) -> Result<()> {
    let role_db = sqlx::query_as!(RoleDbo, "SELECT * FROM roles WHERE name = ?", name,)
        .fetch_one(conn)
        .await?;

    sqlx::query!("DELETE FROM users_roles WHERE id = ?", role_db.id)
        .execute(conn)
        .await?;

    Ok(())
}
