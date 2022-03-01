// Copyright 2022, NAMIB Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use namib_controller::services::device_config_service::{
    get_configured_controllers_for_device, remove_device_configurations, update_device_configurations_from_file,
};
use tokio::fs;

mod lib;

#[tokio::test(flavor = "multi_thread")]
async fn test_device_config_loading() -> namib_controller::error::Result<()> {
    let ctx = lib::IntegrationTestContext::new("test_device_config_loading").await;

    let d = tempfile::tempdir()?;
    let filepath = format!("{}/{}", d.path().to_str().unwrap(), "device-config.yaml");

    let yaml = r#"my-controller-mappings:
  # the lightbulb on the third floor is still from that old manufacturer
  - url: "https://manufacturer.com/bulb"
    my-controller:
      - "https://manufacturer.com/bridge"
      - "urn:ietf:params:mud:ntp"
  # that other device
  - url: "https://company.com/thing"
    # allow it to use DNS
    my-controller: [ "urn:ietf:params:mud:dns" ]
"#;

    fs::write(&filepath, yaml).await?;

    update_device_configurations_from_file(&ctx.db_conn, &filepath).await?;

    {
        let controllers = get_configured_controllers_for_device("https://manufacturer.com/bulb", &ctx.db_conn).await?;
        assert_eq!(controllers.len(), 2);
        assert!(controllers.contains(&"https://manufacturer.com/bridge".to_string()));
        assert!(controllers.contains(&"urn:ietf:params:mud:ntp".to_string()));
    }
    {
        let controllers = get_configured_controllers_for_device("https://company.com/thing", &ctx.db_conn).await?;
        assert_eq!(controllers.len(), 1);
        assert!(controllers.contains(&"urn:ietf:params:mud:dns".to_string()));
    }

    remove_device_configurations(&ctx.db_conn).await?;

    {
        let controllers = get_configured_controllers_for_device("https://manufacturer.com/bulb", &ctx.db_conn).await?;
        assert_eq!(controllers.len(), 0);
    }
    {
        let controllers = get_configured_controllers_for_device("https://company.com/thing", &ctx.db_conn).await?;
        assert_eq!(controllers.len(), 0);
    }

    Ok(())
}
