use crate::{
    db::DbConnection,
    error::Result,
    models::{Role, RoleDbo, User, UserDbo},
    services::role_service,
};

// Database methods
pub async fn get_all(conn: &DbConnection) -> Result<Vec<User>> {
    let usrs = sqlx::query!(
"select
	u.id as user_id
	, username
	, password
	, salt
	, cast((select group_concat(name) from (select name from users_roles ur join roles r on r.id = ur.role_id where user_id = u.id)) as text) as roles
	, cast((select group_concat(role_id) from (select role_id from users_roles ur join roles r on r.id = ur.role_id where user_id = u.id)) as text) as roles_ids
	, cast((select group_concat(permissions) from (select permissions from users_roles ur join roles r on r.id = ur.role_id where user_id = u.id)) as text) as permissions
from
	users u")
        .fetch_all(conn)
        .await?;

    Ok(usrs
        .into_iter()
        .map(|usr| User {
            id: usr.user_id,
            username: usr.username,
            password: usr.password,
            salt: usr.salt,
            roles: get_roles(&usr.roles_ids, &usr.roles),
            permissions: usr.permissions.split(',').map(ToOwned::to_owned).collect(),
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
    let usr_count = sqlx::query!("select count(*) as count from users")
        .fetch_one(conn)
        .await?
        .count;
    Ok(usr_count > 0)
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

    let user = User {
        id: usr.id,
        username: usr.username,
        password: usr.password,
        salt: usr.salt,
        permissions: roles
            .iter()
            .flat_map(|r| r.permissions.split(',').map(ToOwned::to_owned))
            .collect(),
        roles: roles.into_iter().map(Role::from).collect(),
    };

    Ok(user)
}

pub async fn insert(user: User, conn: &DbConnection) -> Result<i64> {
    let result = sqlx::query!(
        "insert into users (username, password, salt) values (?, ?, ?)",
        user.username,
        user.password,
        user.salt
    )
    .execute(conn)
    .await?;

    let user_count = sqlx::query!("select count(*) as count from users")
        .fetch_one(conn)
        .await?
        .count;

    if user_count == 1 {
        role_service::role_add_to_user(conn, result.last_insert_rowid(), role_service::ROLE_ID_ADMIN).await?;
    }

    Ok(result.last_insert_rowid())
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

pub async fn update_username(id: i64, user: &User, conn: &DbConnection) -> Result<u64> {
    let upd_count = sqlx::query!("update users set username = ? where id = ?", user.username, id)
        .execute(conn)
        .await?;

    Ok(upd_count.rows_affected())
}

pub async fn update_password(id: i64, user: &User, conn: &DbConnection) -> Result<u64> {
    let upd_count = sqlx::query!(
        "update users set password = ?, salt = ? where id = ?",
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
