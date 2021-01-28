use crate::{
    db::DbConnection,
    error::Result,
    models::{RoleDbo, User, UserConfig, UserDbo},
};
use sqlx::Done;

// Database methods
pub async fn get_all(conn: &DbConnection) -> Result<Vec<User>> {
    let usrs: Vec<_> =
        sqlx::query!("select user_id, username, password, salt, cast(group_concat(name) as text) as roles, cast(group_concat(permissions) as text) as permissions from users u, users_roles m, roles r where u.id = m.user_id and r.id = m.role_id")
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

pub async fn find_by_id(id: i64, conn: &DbConnection) -> Result<User> {
    let usr = sqlx::query_as!(UserDbo, "select * from users where id = ?", id)
        .fetch_one(conn)
        .await?;

    Ok(add_user_roles(usr, conn).await?)
}

pub async fn find_by_username(username: &str, conn: &DbConnection) -> Result<User> {
    let usr = sqlx::query_as!(UserDbo, "select * from users where username = ?", username)
        .fetch_one(conn)
        .await?;

    Ok(add_user_roles(usr, conn).await?)
}

async fn add_user_roles(usr: UserDbo, conn: &DbConnection) -> Result<User> {
    let roles: Vec<RoleDbo> = sqlx::query_as!(
        RoleDbo,
        "select * from roles where id in (select role_id from users_roles where user_id = ?)",
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

pub async fn insert(user: User, conn: &DbConnection) -> Result<u64> {
    let ins_count = sqlx::query!(
        "insert into users (username, password, salt) values (?, ?, ?)",
        user.username,
        user.password,
        user.salt
    )
    .execute(conn)
    .await?;

    Ok(ins_count.rows_affected())
}

pub async fn update(id: i64, user: &User, conn: &DbConnection) -> Result<u64> {
    let upd_count = sqlx::query!(
        "update users set username = ?, password = ?, salt = ? where id = ?",
        user.username,
        user.password,
        user.salt,
        id
    )
    .execute(conn)
    .await?;

    Ok(upd_count.rows_affected())
}

pub async fn delete(id: i64, conn: &DbConnection) -> Result<u64> {
    let del_count = sqlx::query!("delete from users where id = ?", id).execute(conn).await?;

    Ok(del_count.rows_affected())
}

pub async fn get_all_roles(conn: &DbConnection) -> Result<Vec<RoleDbo>> {
    Ok(sqlx::query_as!(RoleDbo, "select * from roles").fetch_all(conn).await?)
}

pub async fn get_all_configs_for_user(user_id: i64, conn: &DbConnection) -> Result<Vec<UserConfig>> {
    Ok(
        sqlx::query_as!(UserConfig, "select * from user_configs where user_id = ?", user_id)
            .fetch_all(conn)
            .await?,
    )
}

pub async fn get_config_for_user(user_id: i64, key: &str, conn: &DbConnection) -> Result<UserConfig> {
    Ok(sqlx::query_as!(
        UserConfig,
        "select * from user_configs where user_id = ? and key = ?",
        user_id,
        key
    )
    .fetch_one(conn)
    .await?)
}

async fn update_config_for_user(user_id: i64, key: &str, value: &str, conn: &DbConnection) -> Result<u64> {
    let upd_count = sqlx::query!(
        "update user_configs set value = ? where key = ? and user_id = ?",
        value,
        key,
        user_id
    )
    .execute(conn)
    .await?;

    debug!("Updating key {:?} with value {:?} for user {:?}", key, value, user_id);

    Ok(upd_count.rows_affected())
}

async fn add_config_for_user(user_id: i64, key: &str, value: &str, conn: &DbConnection) -> Result<u64> {
    let ins_count = sqlx::query!(
        "insert into user_configs (key, user_id, value) values (?, ?, ?)",
        key,
        user_id,
        value
    )
    .execute(conn)
    .await?;

    debug!("Inserting key {:?} with value {:?} for user {:?}", key, value, user_id);

    Ok(ins_count.rows_affected())
}

pub async fn upsert_config_for_user(user_id: i64, key: &str, value: &str, conn: &DbConnection) -> Result<u64> {
    let existing_config: Vec<UserConfig> = sqlx::query_as!(
        UserConfig,
        "select * from user_configs where user_id = ? and key = ?",
        user_id,
        key
    )
    .fetch_all(conn)
    .await?;

    return if existing_config.is_empty() {
        Ok(add_config_for_user(user_id, key, value, conn).await?)
    } else {
        Ok(update_config_for_user(user_id, key, value, conn).await?)
    };
}

pub async fn delete_config_for_user(user_id: i64, key: &str, conn: &DbConnection) -> Result<u64> {
    let del_count = sqlx::query!("delete from user_configs where key = ? and user_id = ?", key, user_id)
        .execute(conn)
        .await?;

    debug!("Deleting key {:?} for user {:?}", key, user_id);

    Ok(del_count.rows_affected())
}
