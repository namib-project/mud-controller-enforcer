extern crate namib_mud_controller;

mod lib;

#[cfg(test)]
mod config_integration {
    use crate::lib;
    use namib_mud_controller::services::config_service;

    #[actix_rt::test]
    async fn get_nothing() {
        let ctx = lib::IntegrationTestContext::new("get_nothing").await;

        assert!(
            config_service::get_config_value("should-be-nothing".to_string(), &ctx.db_conn)
                .await
                .is_err(),
            "Non-existing config value was existing!"
        );
    }

    #[actix_rt::test]
    async fn set_get_something() {
        let ctx = lib::IntegrationTestContext::new("set_get_something").await;

        config_service::set_config_value("some".to_string(), "thing".to_string(), &ctx.db_conn)
            .await
            .unwrap();
        assert_eq!(
            config_service::get_config_value("some".to_string(), &ctx.db_conn)
                .await
                .unwrap(),
            "thing"
        );
    }

    #[actix_rt::test]
    async fn delete_something() {
        let ctx = lib::IntegrationTestContext::new("delete_something").await;

        config_service::set_config_value("some".to_string(), "thing".to_string(), &ctx.db_conn)
            .await
            .unwrap();
        assert_eq!(
            config_service::get_config_value("some".to_string(), &ctx.db_conn)
                .await
                .unwrap(),
            "thing"
        );

        config_service::delete_config_key("some".to_string(), &ctx.db_conn)
            .await
            .unwrap();
        assert!(
            config_service::get_config_value("some".to_string(), &ctx.db_conn)
                .await
                .is_err(),
            "Non-existing config value was existing!"
        );
    }
}
