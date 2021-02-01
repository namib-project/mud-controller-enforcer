extern crate namib_mud_controller;

mod lib;

#[cfg(test)]
mod config_integration {
    use crate::lib;
    use namib_mud_controller::{models::Config, services::config_service};

    #[actix_rt::test]
    async fn get_nothing() {
        let ctx = lib::IntegrationTestContext::new("get_nothing").await;

        assert!(
            config_service::get_config_value(&"should-be-nothing".to_string(), &ctx.db_conn)
                .await
                .is_err(),
            "Non-existing config value was existing!"
        );
    }

    #[actix_rt::test]
    async fn set_get_something() {
        let ctx = lib::IntegrationTestContext::new("set_get_something").await;

        config_service::set_config_value(&"some".to_string(), &"thing".to_string(), &ctx.db_conn)
            .await
            .unwrap();
        assert_eq!(
            config_service::get_config_value(&"some".to_string(), &ctx.db_conn)
                .await
                .unwrap(),
            "thing"
        );
    }

    #[actix_rt::test]
    async fn delete_something() {
        let ctx = lib::IntegrationTestContext::new("delete_something").await;

        config_service::set_config_value(&"some".to_string(), &"thing".to_string(), &ctx.db_conn)
            .await
            .unwrap();
        assert_eq!(
            config_service::get_config_value(&"some".to_string(), &ctx.db_conn)
                .await
                .unwrap(),
            "thing"
        );

        assert_eq!(
            config_service::delete_config_key(&"some".to_string(), &ctx.db_conn)
                .await
                .unwrap(),
            1
        );
        assert!(
            config_service::get_config_value(&"some".to_string(), &ctx.db_conn)
                .await
                .is_err(),
            "Non-existing config value was existing!"
        );
    }

    #[actix_rt::test]
    async fn get_all() {
        let ctx = lib::IntegrationTestContext::new("get_all").await;

        config_service::set_config_value(&"some".to_string(), &"thing".to_string(), &ctx.db_conn)
            .await
            .unwrap();

        config_service::set_config_value(
            &"stackoverflow".to_string(),
            &"saves lives & our sanity".to_string(),
            &ctx.db_conn,
        )
        .await
        .unwrap();

        config_service::set_config_value(&"actix_with".to_string(), &"sqlx".to_string(), &ctx.db_conn)
            .await
            .unwrap();

        config_service::set_config_value(
            &"longest_german_word".to_string(),
            &"Rinderkennzeichnungsfleischetikettierungsüberwachungsaufgabenübertragungsgesetz".to_string(),
            &ctx.db_conn,
        )
        .await
        .unwrap();

        assert_eq!(
            config_service::get_all_config_data(&ctx.db_conn).await.unwrap(),
            vec![
                Config {
                    key: "some".to_string(),
                    value: "thing".to_string()
                },
                Config {
                    key: "stackoverflow".to_string(),
                    value: "saves lives & our sanity".to_string()
                },
                Config {
                    key: "actix_with".to_string(),
                    value: "sqlx".to_string()
                },
                Config {
                    key: "longest_german_word".to_string(),
                    value: "Rinderkennzeichnungsfleischetikettierungsüberwachungsaufgabenübertragungsgesetz"
                        .to_string()
                }
            ]
        );
    }
}
