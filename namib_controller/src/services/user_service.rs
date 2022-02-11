// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use chrono::Utc;

use crate::{
    db::DbConnection,
    error::Result,
    models::{Role, RoleDbo, User, UserDbo},
    services::role_service,
};

// Database methods
pub async fn get_all(conn: &DbConnection) -> Result<Vec<User>> {
    #[cfg(not(feature = "postgres"))]
    let usrs = sqlx::query!(
r#"select
	u.id as user_id
	, username
	, password
	, salt
	, last_interaction
	, (select group_concat(name) from (select name from users_roles ur join roles r on r.id = ur.role_id where user_id = u.id)) as "roles: Option<String>"
	, (select group_concat(role_id) from (select role_id from users_roles ur join roles r on r.id = ur.role_id where user_id = u.id)) as "roles_ids: Option<String>"
	, (select group_concat(permissions) from (select permissions from users_roles ur join roles r on r.id = ur.role_id where user_id = u.id)) as "permissions: Option<String>"
from
	users u"#)
        .fetch_all(conn)
        .await?;
    #[cfg(feature = "postgres")]
        let usrs =  sqlx::query!(
r#"select
	u.id as user_id
	, username
	, password
	, salt
	, last_interaction
	, (select string_agg(name, ',') from (select name from users_roles ur join roles r on r.id = ur.role_id where user_id = u.id) as roles) as roles
	, (select string_agg(role_id::text, ',') from (select role_id from users_roles ur join roles r on r.id = ur.role_id where user_id = u.id) as roles_ids) as roles_ids
	, (select string_agg(permissions, ',') from (select permissions from users_roles ur join roles r on r.id = ur.role_id where user_id = u.id) as permissions) as permissions
from
	users u"#)
        .fetch_all(conn)
        .await?;

    Ok(usrs
        .into_iter()
        .map(|usr| User {
            id: usr.user_id,
            username: usr.username,
            password: usr.password,
            salt: usr.salt,
            last_interaction: usr.last_interaction,
            roles: get_roles(&usr.roles_ids.unwrap_or_default(), &usr.roles.unwrap_or_default()),
            permissions: usr
                .permissions
                .unwrap_or_default()
                .split(',')
                .filter(|p| !p.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
        })
        .collect())
}

fn get_roles(ids: &str, names: &str) -> Vec<Role> {
    let mut res = Vec::new();
    let mut id_iter = ids.split(',');
    let mut name_iter = names.split(',');
    loop {
        res.push(Role {
            id: match id_iter.next().and_then(|id| id.parse().ok()) {
                Some(id) => id,
                None => break,
            },
            name: match name_iter.next() {
                Some(name) => name.to_string(),
                None => break,
            },
        });
    }
    res
}

pub async fn has_any_users(conn: &DbConnection) -> Result<bool> {
    let usr_count = sqlx::query!(r#"SELECT COUNT(*) AS "count!" FROM users"#)
        .fetch_one(conn)
        .await?
        .count;
    Ok(usr_count > 0)
}

pub async fn find_by_id(id: i64, conn: &DbConnection) -> Result<User> {
    let usr = sqlx::query_as!(UserDbo, "SELECT * FROM users WHERE id = $1", id)
        .fetch_one(conn)
        .await?;

    Ok(with_roles(usr, conn).await?)
}

pub async fn find_by_username(username: &str, conn: &DbConnection) -> Result<User> {
    let usr = sqlx::query_as!(UserDbo, "SELECT * FROM users WHERE username = $1", username)
        .fetch_one(conn)
        .await?;

    Ok(with_roles(usr, conn).await?)
}

async fn with_roles(usr: UserDbo, conn: &DbConnection) -> Result<User> {
    let roles: Vec<RoleDbo> = sqlx::query_as!(
        RoleDbo,
        "SELECT * FROM roles WHERE id IN (SELECT role_id FROM users_roles WHERE user_id = $1)",
        usr.id
    )
    .fetch_all(conn)
    .await?;

    let user = User {
        id: usr.id,
        username: usr.username,
        password: usr.password,
        salt: usr.salt,
        last_interaction: usr.last_interaction,
        permissions: roles
            .iter()
            .flat_map(|r| r.permissions.split(',').map(ToOwned::to_owned))
            .collect(),
        roles: roles.into_iter().map(Role::from).collect(),
    };

    Ok(user)
}

pub async fn insert(user: User, conn: &DbConnection) -> Result<i64> {
    #[cfg(not(feature = "postgres"))]
    let result = sqlx::query!(
        "INSERT INTO users (username, password, salt) VALUES (?, ?, ?)",
        user.username,
        user.password,
        user.salt
    )
    .execute(conn)
    .await?
    .last_insert_rowid();

    #[cfg(feature = "postgres")]
    let result = sqlx::query!(
        "INSERT INTO users (username, password, salt) VALUES ($1, $2, $3) RETURNING id",
        user.username,
        user.password,
        user.salt
    )
    .fetch_one(conn)
    .await?
    .id;

    let user_count = sqlx::query!(r#"SELECT COUNT(*) AS "count!" FROM users"#)
        .fetch_one(conn)
        .await?
        .count;

    if user_count == 1 {
        role_service::add_role_to_user(conn, result, role_service::ROLE_ID_ADMIN).await?;
    }

    Ok(result)
}

pub async fn update(user: &User, conn: &DbConnection) -> Result<bool> {
    let upd_count = sqlx::query!(
        "update users SET username = $1, password = $2, salt = $3 WHERE id = $4",
        user.username,
        user.password,
        user.salt,
        user.id
    )
    .execute(conn)
    .await?;

    Ok(upd_count.rows_affected() == 1)
}

pub async fn update_username(id: i64, username: &str, conn: &DbConnection) -> Result<bool> {
    let upd_count = sqlx::query!("UPDATE users SET username = $1 where id = $2", username, id)
        .execute(conn)
        .await?;

    Ok(upd_count.rows_affected() == 1)
}

pub async fn update_password(id: i64, password: &str, conn: &DbConnection) -> Result<bool> {
    let salt = User::generate_salt();
    let password = User::hash_password(password, &salt)?;
    let upd_count = sqlx::query!(
        "UPDATE users SET password = $1, salt = $2 where id = $3",
        password,
        salt,
        id
    )
    .execute(conn)
    .await?;

    Ok(upd_count.rows_affected() == 1)
}

pub async fn delete(id: i64, conn: &DbConnection) -> Result<bool> {
    let del_count = sqlx::query!("DELETE FROM users WHERE id = $1", id)
        .execute(conn)
        .await?;

    Ok(del_count.rows_affected() == 1)
}

pub async fn get_all_roles(conn: &DbConnection) -> Result<Vec<RoleDbo>> {
    Ok(sqlx::query_as!(RoleDbo, "SELECT * FROM roles").fetch_all(conn).await?)
}

pub async fn update_last_interaction_stamp(id: i64, conn: &DbConnection) -> Result<bool> {
    let utc_now = Utc::now().naive_utc();
    let upd_count = sqlx::query!("UPDATE users SET last_interaction = $1 where id = $2", utc_now, id)
        .execute(conn)
        .await?;

    Ok(upd_count.rows_affected() == 1)
}
