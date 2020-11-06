use diesel::prelude::*;

use crate::db::ConnectionType;
use crate::error::*;
use crate::schema::{roles, users};

use crate::models::user_model::{User, UserRole, Role};

#[derive(Insertable)]
#[table_name = "users"]
pub struct InsertableUser {
    pub username: String,
    pub password: String,
    pub salt: Vec<u8>,
}

impl From<User> for InsertableUser {
    fn from(user: User) -> InsertableUser {
        InsertableUser {
            username: user.username,
            password: user.password,
            salt: user.salt,
        }
    }
}

// Database methods
pub fn get_all(conn: &ConnectionType) -> Result<Vec<User>> {
    let usrs = users::table.load::<User>(conn)?;

    Ok(usrs)
}

pub fn find_by_id(id: &i32, conn: &ConnectionType) -> Result<User> {
    let usr = users::table.find(id)
        .get_result::<User>(conn)?;

    Ok(usr)
}

pub fn find_by_username(username: &str, conn: &ConnectionType) -> Result<User> {
    let usr = users::table
        .filter(users::username.eq(username))
        .first::<User>(conn)?;

    Ok(usr)
}

pub fn insert(user: User, conn: &ConnectionType) -> Result<usize> {
    let ins_count = diesel::insert_into(users::table)
        .values(&InsertableUser::from(user))
        .execute(conn)?;

    Ok(ins_count)
}

pub fn update(id: i32, user: User, conn: &ConnectionType) -> Result<usize> {
    let upd_count = diesel::update(users::table.find(id))
        .set(&user)
        .execute(conn)?;

    Ok(upd_count)
}

pub fn delete(id: i32, conn: &ConnectionType) -> Result<usize> {
    let del_count = diesel::delete(users::table.find(id))
        .execute(conn)?;

    Ok(del_count)
}

pub fn get_roles(user: &User, conn: &ConnectionType) -> Result<Vec<Role>> {
    let roles = UserRole::belonging_to(user)
        .inner_join(roles::table)
        .select(roles::all_columns)
        .load::<Role>(conn)?;

    Ok(roles)
}

pub fn get_permissions(user: &User, conn: &ConnectionType) -> Result<Vec<String>> {
    let roles = get_roles(user, conn)?;

    let permissions = roles
        .iter()
        .map(|role| role.permissions())
        .flatten()
        .map(|permission| String::from(permission))
        .collect();

    Ok(permissions)
}
