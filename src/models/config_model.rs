use crate::schema::config;
use schemars::JsonSchema;

/// The config has a very simple structure. A key (which is also a the primary key) and a value (which is a string)
/// You can use it to store anything you need as Key-Values in the Database
#[derive(Queryable, Identifiable, Insertable, AsChangeset, Serialize, Deserialize, Clone, JsonSchema)]
#[table_name = "config"]
#[primary_key(key)]
pub struct Config {
    pub key: String,
    pub value: String,
}
