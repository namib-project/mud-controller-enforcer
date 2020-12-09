extern crate diesel;
extern crate namib_mud_controller;

mod lib;

#[cfg(test)]
mod config_integration {
    use crate::lib;
    use namib_mud_controller::services::config_service;

    #[tokio::test]
    async fn get_nothing() {
        let ctx = lib::IntegrationTestContext::new("get_nothing");
        let pool = ctx.db_pool.clone().expect("Invalid DB connection pool");

        assert!(
            config_service::get_config_value("should-be-nothing".to_string(), pool).await.is_err(),
            "Non-existing config value was existing!"
        );
    }

    #[tokio::test]
    async fn set_get_something() {
        let ctx = lib::IntegrationTestContext::new("set_get_something");
        let pool = ctx.db_pool.clone().expect("Invalid DB connection pool");

        config_service::set_config_value("some".to_string(), "thing".to_string(), pool.clone()).await.unwrap();
        assert_eq!(config_service::get_config_value("some".to_string(), pool.clone()).await.unwrap(), "thing");
    }

    #[tokio::test]
    async fn delete_something() {
        let ctx = lib::IntegrationTestContext::new("delete_something");
        let pool = ctx.db_pool.clone().expect("Invalid DB connection pool");

        config_service::set_config_value("some".to_string(), "thing".to_string(), pool.clone()).await.unwrap();
        assert_eq!(config_service::get_config_value("some".to_string(), pool.clone()).await.unwrap(), "thing");

        config_service::delete_config_key("some".to_string(), pool.clone()).await.unwrap();
        assert!(
            config_service::get_config_value("some".to_string(), pool.clone()).await.is_err(),
            "Non-existing config value was existing!"
        );
    }
}
