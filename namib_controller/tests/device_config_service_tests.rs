// Copyright 2022, NAMIB Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use namib_controller::services::device_config_service::get_configured_dns_servers;
use namib_controller::services::device_config_service::get_configured_ntp_servers;
use namib_controller::{
    models::ConfiguredControllerMapping,
    services::device_config_service::{
        get_configured_controllers_for_device, remove_device_configurations, update_device_configurations_from_file,
    },
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
      - "192.168.2.12"
  # that other device
  - url: "https://company.com/thing"
    # allow it to use DNS
    my-controller: [ "urn:ietf:params:mud:dns" ]

servers:
  ntp:
    # maybe I set up a local NTP server and went through the trouble
    # of writing a MUD file for it, so I name it by MUD-URL?
    - "https://me.org/my-ntp-server-device"
    # maybe i went through the trouble of checking what IP-address a
    # manufacturer's NTP server has, and hardcode that here?
    - "123.45.67.89"
  dns:
    # maybe I just want to specify Google's Servers?
    - "8.8.8.8"
    - "8.8.4.4"
    - "2001:4860:4860::8888"
    - "2001:4860:4860::8844"
"#;

    fs::write(&filepath, yaml).await?;

    update_device_configurations_from_file(&ctx.db_conn, &filepath).await?;

    {
        let controllers = get_configured_controllers_for_device("https://manufacturer.com/bulb", &ctx.db_conn).await?;
        assert_eq!(controllers.len(), 3);
        assert!(controllers.contains(&ConfiguredControllerMapping::Uri(
            "https://manufacturer.com/bridge".to_string()
        )));
        assert!(controllers.contains(&ConfiguredControllerMapping::Uri("urn:ietf:params:mud:ntp".to_string())));
        assert!(controllers.contains(&ConfiguredControllerMapping::Ip("192.168.2.12".parse().unwrap())));
    }
    {
        let controllers = get_configured_controllers_for_device("https://company.com/thing", &ctx.db_conn).await?;
        assert_eq!(controllers.len(), 1);
        assert!(controllers.contains(&ConfiguredControllerMapping::Uri("urn:ietf:params:mud:dns".to_string())));
    }
    {
        let servers = get_configured_ntp_servers(&ctx.db_conn).await?;
        assert_eq!(servers.len(), 2);
        assert!(servers.contains(&"https://me.org/my-ntp-server-device".to_string()));
        assert!(servers.contains(&"123.45.67.89".to_string()));
    }
    {
        let servers = get_configured_dns_servers(&ctx.db_conn).await?;
        assert_eq!(servers.len(), 4);
        assert!(servers.contains(&"8.8.8.8".to_string()));
        assert!(servers.contains(&"8.8.4.4".to_string()));
        assert!(servers.contains(&"2001:4860:4860::8888".to_string()));
        assert!(servers.contains(&"2001:4860:4860::8844".to_string()));
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
