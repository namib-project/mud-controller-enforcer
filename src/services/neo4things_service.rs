use std::env;

use backoff::{backoff::Backoff, future::retry, ExponentialBackoff};
use lazy_static::lazy_static;
use neo4things_api::{
    apis::{configuration::Configuration, mud_api, thing_api},
    models::{Acl, Description, Thing},
};
use tokio::time::Duration;

use crate::{error, error::Result, models::Device, routes::dtos::GuessDto, VERSION};

lazy_static! {
    /// The configuration for connecting to the neo4jthings service.
    /// We could configure the base_url here too
    static ref N4T_CONFIG: Configuration = Configuration {
        base_path: env::var("NEO4THINGS_URL").expect("NEO4THINGS_URL env missing"),
        basic_auth: Some((
            env::var("NEO4THINGS_USER").expect("NEO4THINGS_USER env missing"),
            Some(env::var("NEO4THINGS_PASS").expect("NEO4THINGS_PASS env missing"))
        )),
        user_agent: Some(format!("namib_mud_controller {}", VERSION)),
        ..Default::default()
    };
}

/// Add a device in the neo4jthings service.
/// This operation should be run in the background as it is failsafe.
pub async fn add_device(id: i64, device: Device) {
    let identifier = device.mac_or_duid();
    debug!("adding device to neo4jthings: {}", identifier);
    if let Err(e) = retry(backoff_policy(), || async {
        match thing_api::thing_create(
            &N4T_CONFIG,
            Thing {
                serial: id.to_string(),
                mac_addr: identifier.clone(),
                ipv4_addr: device
                    .ipv4_addr
                    .map_or_else(|| "0.0.0.0".to_string(), |ip| ip.to_string()),
                ipv6_addr: device.ipv6_addr.map_or_else(|| "::".to_string(), |ip| ip.to_string()),
                hostname: device.hostname.to_string(),
            },
        )
        .await
        {
            Ok(_) => Ok(()),
            Err(e) => {
                warn!("Error while adding thing {:?}", e);
                Err(backoff::Error::Transient(e))
            },
        }
    })
    .await
    {
        error!("Failed to add thing {:?}", e)
    }
}

/// Add a connection to a device in the neo4jthings service.
/// This operation should be run in the background as it is failsafe.
pub async fn add_device_connection(device: Device, connection: String) {
    let identifier = device.mac_or_duid();
    debug!("adding device connection to neo4jthings: {} {}", identifier, connection);
    if let Err(e) = retry(backoff_policy(), || async {
        Ok(thing_api::thing_connections_create(
            &N4T_CONFIG,
            &identifier,
            Acl {
                name: connection.clone(),
                _type: "4t".to_string(), // TODO 6t ?
                acl_dns: connection.clone(),
                port: vec![],
                direction_initiated: "from-device".to_string(),
                forwarding: "accept".to_string(),
                timestamp: None,
            },
        )
        .await?)
    })
    .await
    {
        error!("Failed to add thing connection {:?}", e)
    }
}

/// Query the neo4jthings service for possible mud-urls that match a given device.
/// This operation should be run directly, since we are interested in the results.
pub async fn guess_thing(device: Device) -> Result<Vec<GuessDto>> {
    let identifier = device.mac_or_duid();
    let result = mud_api::mud_guess_thing_list(&N4T_CONFIG, &identifier, None)
        .await
        .or_else(|e| error::Neo4ThingsError { message: e.to_string() }.fail())?;

    Ok(result
        .results
        .unwrap()
        .into_iter()
        .map(|mud| GuessDto {
            mud_url: mud.mud_url,
            manufacturer_name: Some(mud.mud_signature),
            model_name: Some(mud.name),
        })
        .collect())
}

/// Notify the neo4jthings service that a `mud_url` was chosen for a given device.
/// This operation should be run in the background as it is failsafe.
pub async fn describe_thing(mac_or_duid: String, mud_url: String) {
    debug!("describing thing to neo4jthings: {} {}", mac_or_duid, mud_url);
    if let Err(e) = retry(backoff_policy(), || async {
        Ok(thing_api::thing_describe_create(
            &N4T_CONFIG,
            &mac_or_duid,
            Description {
                mud_url: mud_url.clone(),
                mac_addr: mac_or_duid.clone(),
            },
        )
        .await?)
    })
    .await
    {
        error!("Failed to describe thing {:?}", e)
    }
}

fn backoff_policy() -> ExponentialBackoff {
    let mut eb = ExponentialBackoff {
        initial_interval: Duration::from_secs(10),
        max_interval: Duration::from_secs(60),
        max_elapsed_time: Some(Duration::from_secs(60 * 15)),
        ..Default::default()
    };
    eb.reset();
    eb
}
