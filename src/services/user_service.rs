use crate::{
    db::ConnectionType,
    error::Result,
    models::user_model::{Role, User},
};
use sqlx::Done;

// Database methods
pub async fn get_all(conn: &ConnectionType) -> Result<Vec<User>> {
    let usrs = sqlx::query_as!(User, "select * from users").fetch_all(conn).await?;

    Ok(usrs)
}

pub async fn find_by_id(id: i64, conn: &ConnectionType) -> Result<User> {
    let usr = sqlx::query_as!(User, "select * from users where id = ?", id)
        .fetch_one(conn)
        .await?;

    Ok(usr)
}

pub async fn find_by_username(username: &str, conn: &ConnectionType) -> Result<User> {
    let usr = sqlx::query_as!(User, "select * from users where username = ?", username)
        .fetch_one(conn)
        .await?;

    Ok(usr)
}

pub async fn insert(user: User, conn: &ConnectionType) -> Result<u64> {
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

pub async fn update(id: i64, user: &User, conn: &ConnectionType) -> Result<u64> {
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

pub async fn delete(id: i64, conn: &ConnectionType) -> Result<u64> {
    let del_count = sqlx::query!("delete from users where id = ?", id).execute(conn).await?;

    Ok(del_count.rows_affected())
}

pub async fn get_roles(user: &User, conn: &ConnectionType) -> Result<Vec<Role>> {
    let roles = sqlx::query_as!(
        Role,
        "select * from roles where id in (select role_id from users_roles where user_id = ?)",
        user.id
    )
    .fetch_all(conn)
    .await?;

    Ok(roles)
}

pub async fn get_permissions(user: &User, conn: &ConnectionType) -> Result<Vec<String>> {
    let roles = get_roles(user, conn).await?;

    let permissions = roles.iter().flat_map(Role::permissions).map(String::from).collect();

    Ok(permissions)
}
