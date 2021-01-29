use crate::db::DbConnection;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone)]
pub struct ActixDataWrapper {
    pub pool: DbConnection,
    pub refresh_tokens: Arc<Mutex<HashMap<i64, Vec<String>>>>,
}
