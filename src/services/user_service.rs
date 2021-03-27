use crate::{
    db::DbConnection,
    error::Result,
    models::{RoleDbo, User, UserDbo},
    services::role_service,
};

// Database methods
pub async fn get_all(conn: &DbConnection) -> Result<Vec<User>> {
    #[cfg(feature = "sqlite")]
    let usrs: Vec<_> =
        sqlx::query!("SELECT user_id, username, password, salt, CAST(group_concat(r.name) AS TEXT) AS roles, CAST(group_concat(r.permissions) AS TEXT) AS permissions FROM users u, users_roles m, roles r WHERE u.id = m.user_id AND r.id = m.role_id")
            .fetch_all(conn)
            .await?;

    #[cfg(feature = "postgres")]
    let usrs: Vec<_> =
        sqlx::query!("SELECT user_id, username, password, salt, CAST(string_agg(r.name, ',') AS TEXT) AS roles, CAST(string_agg(r.permissions, ',') AS TEXT) AS permissions FROM users u, users_roles m, roles r WHERE u.id = m.user_id AND r.id = m.role_id GROUP BY m.user_id, u.id")
            .fetch_all(conn)
            .await?;

    Ok(usrs
        .into_iter()
        .map(|usr| User {
            id: usr.user_id,
            username: usr.username,
            password: usr.password,
            salt: usr.salt,
            roles: usr
                .roles
                .map(|r| r.split(',').map(ToOwned::to_owned).collect())
                .unwrap_or_default(),
            permissions: usr
                .permissions
                .map(|p| p.split(',').map(ToOwned::to_owned).collect())
                .unwrap_or_default(),
        })
        .collect())
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

    Ok(add_user_roles(usr, conn).await?)
}

pub async fn find_by_username(username: &str, conn: &DbConnection) -> Result<User> {
    let usr = sqlx::query_as!(UserDbo, "SELECT * FROM users WHERE username = $1", username)
        .fetch_one(conn)
        .await?;

    Ok(add_user_roles(usr, conn).await?)
}

async fn add_user_roles(usr: UserDbo, conn: &DbConnection) -> Result<User> {
    let roles: Vec<RoleDbo> = sqlx::query_as!(
        RoleDbo,
        "SELECT * FROM roles WHERE id IN (SELECT role_id FROM users_roles WHERE user_id = $1)",
        usr.id
    )
    .fetch_all(conn)
    .await?;

    Ok(User {
        id: usr.id,
        username: usr.username,
        password: usr.password,
        salt: usr.salt,
        permissions: roles
            .iter()
            .flat_map(|r| r.permissions.split(',').map(ToOwned::to_owned))
            .collect(),
        roles: roles.into_iter().map(|r| r.name).collect(),
    })
}

pub async fn insert(user: User, conn: &DbConnection) -> Result<i64> {
    #[cfg(feature = "sqlite")]
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
        role_service::role_add_to_user(conn, result, role_service::ROLE_ID_ADMIN).await?;
    }

    Ok(result)
}

pub async fn update(id: i64, user: &User, conn: &DbConnection) -> Result<bool> {
    let upd_count = sqlx::query!(
        "update users SET username = $1, password = $2, salt = $3 WHERE id = $4",
        user.username,
        user.password,
        user.salt,
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
