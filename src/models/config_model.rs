use crate::schema::*;
use schemars::JsonSchema;

#[derive(Queryable, Identifiable, Insertable, AsChangeset, Serialize, Deserialize, Clone, JsonSchema)]
#[table_name = "config"]
#[primary_key(key)]
pub struct Config {
    pub key: String,
    pub value: String,
}
