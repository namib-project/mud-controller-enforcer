mod lib;
use namib_controller::{
    models::Config,
    services::{config_service, config_service::ConfigKeys, firewall_configuration_service},
};

#[tokio::test(flavor = "multi_thread")]
async fn test_version() {
    let ctx = lib::IntegrationTestContext::new("test_version").await;

    config_service::set_config_value(ConfigKeys::FirewallConfigVersion.as_ref(), u64::MAX, &ctx.db_conn)
        .await
        .unwrap();

    firewall_configuration_service::update_config_version(&ctx.db_conn)
        .await
        .unwrap();

    assert_eq!(
        config_service::get_config_value::<u64>(ConfigKeys::FirewallConfigVersion.as_ref(), &ctx.db_conn)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn get_nothing() {
    let ctx = lib::IntegrationTestContext::new("get_nothing").await;

    assert!(
        config_service::get_config_value::<String>("should-be-nothing", &ctx.db_conn)
            .await
            .is_err(),
        "Non-existing config value was existing!"
    );
}

#[tokio::test(flavor = "multi_thread")]
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

#[tokio::test(flavor = "multi_thread")]
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
        true
    );
    assert!(
        config_service::get_config_value::<String>("some", &ctx.db_conn)
            .await
            .is_err(),
        "Non-existing config value was existing!"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn get_all() {
    let ctx = lib::IntegrationTestContext::new("get_all").await;

    let mut expected_config = config_service::get_all_config_data(&ctx.db_conn).await.unwrap();
    expected_config.append(&mut vec![
        Config {
            key: "some".to_string(),
            value: "thing".to_string(),
        },
        Config {
            key: "stackoverflow".to_string(),
            value: "saves lives & our sanity".to_string(),
        },
        Config {
            key: "actix_with".to_string(),
            value: "sqlx".to_string(),
        },
        Config {
            key: "longest_german_word".to_string(),
            value: "Rinderkennzeichnungsfleischetikettierungsüberwachungsaufgabenübertragungsgesetz".to_string(),
        },
    ]);

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
        expected_config
    );
}
