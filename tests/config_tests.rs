mod lib;
use namib_mud_controller::{models::Config, services::config_service};

#[actix_rt::test]
async fn get_nothing() {
    let ctx = lib::IntegrationTestContext::new("get_nothing").await;

    assert!(
        config_service::get_config_value::<String>("should-be-nothing", &ctx.db_conn)
            .await
            .is_err(),
        "Non-existing config value was existing!"
    );
}

#[actix_rt::test]
async fn set_get_something() {
    let ctx = lib::IntegrationTestContext::new("set_get_something").await;

    config_service::set_config_value("some", "thing", &ctx.db_conn)
        .await
        .unwrap();
    assert_eq!(
        config_service::get_config_value::<String>("some", &ctx.db_conn)
            .await
            .unwrap(),
        "thing"
    );
}

#[actix_rt::test]
async fn delete_something() {
    let ctx = lib::IntegrationTestContext::new("delete_something").await;

    config_service::set_config_value("some", &"thing", &ctx.db_conn)
        .await
        .unwrap();
    assert_eq!(
        config_service::get_config_value::<String>("some", &ctx.db_conn)
            .await
            .unwrap(),
        "thing"
    );

    assert_eq!(
        config_service::delete_config_key("some", &ctx.db_conn).await.unwrap(),
        1
    );
    assert!(
        config_service::get_config_value::<String>("some", &ctx.db_conn)
            .await
            .is_err(),
        "Non-existing config value was existing!"
    );
}

#[actix_rt::test]
async fn get_all() {
    let ctx = lib::IntegrationTestContext::new("get_all").await;

    config_service::set_config_value("some", "thing", &ctx.db_conn)
        .await
        .unwrap();

    config_service::set_config_value("stackoverflow", "saves lives & our sanity", &ctx.db_conn)
        .await
        .unwrap();

    config_service::set_config_value("actix_with", "sqlx", &ctx.db_conn)
        .await
        .unwrap();

    config_service::set_config_value(
        "longest_german_word",
        "Rinderkennzeichnungsfleischetikettierungsüberwachungsaufgabenübertragungsgesetz",
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
                value: "Rinderkennzeichnungsfleischetikettierungsüberwachungsaufgabenübertragungsgesetz".to_string()
            }
        ]
    );
}
