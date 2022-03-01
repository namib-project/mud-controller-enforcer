// Copyright 2022, NAMIB Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

// NOTE:
//   'Device Configuration' in this context refers to device information configured for the system.
//   For example, it can contain the mappings used to implement the `my-controller` MUD ACL matches
//   node augmentation.

use std::io::Read;

use crate::db::DbConnection;
use crate::models::DeviceControllerDbo;

/// Get the configured controllers for the device specified by the given MUD URL.
pub async fn get_configured_controllers_for_device(
    mud_url: &str,
    pool: &DbConnection,
) -> crate::error::Result<Vec<String>> {
    Ok(sqlx::query_as!(
        DeviceControllerDbo,
        "SELECT * FROM device_controllers WHERE url = $1",
        mud_url
    )
    .fetch_all(pool)
    .await?
    .iter()
    .map(|c| c.controller_uri.clone())
    .collect())
}

/// Invoke an update of the device configurations with the data in the given configuration file.
/// Replaces all existing configurations with the configuration from the file.
pub async fn update_device_configurations_from_file(pool: &DbConnection, file: &str) -> crate::error::Result<()> {
    let yaml = get_device_configuration_file_contents(file)?;

    let config = parse_device_configuration_yaml(&yaml);

    match config {
        Ok(config) => Ok(set_device_configurations(pool, &config).await?),
        Err(err) => Err(crate::error::Error::SerdeYamlError { source: err }),
    }
}

/// Remove all device configurations.
pub async fn remove_device_configurations(pool: &DbConnection) -> crate::error::Result<()> {
    remove_device_controller_mappings(pool).await?;
    Ok(())
}

/// Replace existing device configuration in the database with the one passed to it.
async fn set_device_configurations(pool: &DbConnection, config: &DeviceConfigurationData) -> crate::error::Result<()> {
    remove_device_configurations(pool).await?;

    for mapping in &config.my_controller_mappings {
        for controller_uri in &mapping.my_controller {
            debug!("inserting my-controller mapping {}->{}", mapping.url, controller_uri);
            sqlx::query!(
                "INSERT INTO device_controllers (url, controller_uri) VALUES ($1, $2)",
                mapping.url,
                controller_uri
            )
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

async fn remove_device_controller_mappings(pool: &DbConnection) -> crate::error::Result<()> {
    sqlx::query!("DELETE FROM device_controllers").execute(pool).await?;
    Ok(())
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct DeviceConfigurationData {
    #[serde(rename = "my-controller-mappings", default = "Vec::new")]
    my_controller_mappings: Vec<ControllerMapping>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct ControllerMapping {
    url: String,
    #[serde(rename = "my-controller")]
    my_controller: Vec<String>,
}

fn parse_device_configuration_yaml(data: &str) -> Result<DeviceConfigurationData, serde_yaml::Error> {
    let config_result: DeviceConfigurationData = serde_yaml::from_str(data)?;
    Ok(config_result)
}

fn get_device_configuration_file_contents(file: &str) -> crate::error::Result<String> {
    let mut x = std::fs::File::open(file)?;
    let mut yaml = String::new();
    x.read_to_string(&mut yaml)?;

    Ok(yaml)
}

#[test]
fn test_parse_device_configuration_yaml_example() {
    let input = r#"my-controller-mappings:
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
    let expected = DeviceConfigurationData {
        my_controller_mappings: vec![
            ControllerMapping {
                url: "https://manufacturer.com/bulb".to_string(),
                my_controller: vec![
                    "https://manufacturer.com/bridge".to_string(),
                    "urn:ietf:params:mud:ntp".to_string(),
                ],
            },
            ControllerMapping {
                url: "https://company.com/thing".to_string(),
                my_controller: vec!["urn:ietf:params:mud:dns".to_string()],
            },
        ],
    };

    let result = parse_device_configuration_yaml(input);

    match result {
        Ok(result) => {
            assert_eq!(expected, result);
        },
        Err(error) => panic!("{}", error),
    }
}

#[test]
fn test_parse_device_configuration_yaml_empty() {
    let input = r#"foo: "hi, serde doesn't support deserializing empty yaml, even if we have no required fields, so here's a fun little string""#;
    let expected = DeviceConfigurationData {
        my_controller_mappings: vec![],
    };

    let result = parse_device_configuration_yaml(input);

    match result {
        Ok(result) => {
            assert_eq!(expected, result);
        },
        Err(error) => panic!("{}", error),
    }
}
