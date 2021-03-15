use crate::{error, error::Result, models::Device, routes::dtos::GuessDto, VERSION};
use chrono::Utc;
use lazy_static::lazy_static;
use neo4jthings_api::{
    apis::{configuration::Configuration, mud_api, thing_api},
    models::{Acl, Description, Thing},
};
use std::{env, fmt::Debug, future::Future, net::IpAddr};
use tokio::time::{sleep, Duration};

lazy_static! {
    /// The configuration for connecting to the neo4jthings service.
    /// We could configure the base_url here too
    static ref N4JT_CONFIG: Configuration = Configuration {
        basic_auth: Some((
            env::var("NEO4JTHINGS_USER").expect("NEO4JTHINGS_USER env missing"),
            Some(env::var("NEO4JTHINGS_PASS").expect("NEO4JTHINGS_PASS env missing"))
        )),
        user_agent: Some(format!("namib_mud_controller {}", VERSION)),
        ..Default::default()
    };
}

/// Add a device in the neo4jthings service.
/// This operation should be run in the background as it is failsafe.
pub async fn add_device(device: Device) {
    debug!("adding device to neo4jthings: {}", device.ip_addr);
    if let Err(e) = retry_op(|| async {
        thing_api::thing_create(
            &*N4JT_CONFIG,
            Thing {
                serial: device.mac_addr.unwrap().to_string(),
                mac_addr: device.mac_addr.unwrap().to_string(),
                ipv4_addr: match device.ip_addr {
                    IpAddr::V4(addr) => addr.to_string(),
                    IpAddr::V6(_) => "0.0.0.0".to_string(), // TODO blank not allowed?
                },
                ipv6_addr: match device.ip_addr {
                    IpAddr::V4(addr) => addr.to_ipv6_mapped().to_string(), // TODO blank not allowed?
                    IpAddr::V6(addr) => addr.to_string(),
                },
                hostname: device.hostname.to_string(),
            },
        )
        .await
    })
    .await
    {
        error!("Failed to add thing {:?}", e)
    }
}

/// Add a connection to a device in the neo4jthings service.
/// This operation should be run in the background as it is failsafe.
pub async fn add_device_connection(device: Device, connection: String) {
    debug!(
        "adding device connection to neo4jthings: {} {}",
        device.ip_addr, connection
    );
    if let Err(e) = retry_op(|| async {
        thing_api::thing_connections_create(
            &*N4JT_CONFIG,
            &device.mac_addr.unwrap().to_string(), // TODO: duid
            Acl {
                name: "".to_string(), // TODO: name
                _type: if device.ip_addr.is_ipv4() {
                    "4t".to_string()
                } else {
                    "6t".to_string()
                },
                acl_dns: connection.clone(),
                port: vec![],
                direction_initiated: "from-device".to_string(),
                forwarding: "accept".to_string(),
                timestamp: Some(Utc::now().to_rfc3339()),
            },
        )
        .await
    })
    .await
    {
        error!("Failed to add thing connection {:?}", e)
    }
}

/// Query the neo4jthings service for possible mud-urls that match a given device.
/// This operation should be run directly, since we are interested in the results.
pub async fn guess_thing(device: Device) -> Result<Vec<GuessDto>> {
    let result = mud_api::mud_guess_thing_list(&*N4JT_CONFIG, &device.mac_addr.unwrap().to_string(), None)
        .await
        .or_else(|e| error::Neo4jThingsError { message: e.to_string() }.fail())?;

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

/// Notify the neo4jthings service that a mud_url was chosen for a given device.
/// This operation should be run in the background as it is failsafe.
pub async fn describe_thing(mac_addr: String, mud_url: String) {
    debug!("describing thing to neo4jthings: {} {}", mac_addr, mud_url);
    if let Err(e) = retry_op(|| async {
        thing_api::thing_describe_create(
            &*N4JT_CONFIG,
            &mac_addr, // TODO: duid
            Description {
                mud_url: mud_url.clone(),
                mac_addr: mac_addr.clone(),
            },
        )
        .await
    })
    .await
    {
        error!("Failed to describe thing {:?}", e)
    }
}

async fn retry_op<F, T, U, E>(mut f: F) -> std::result::Result<(), E>
where
    F: FnMut() -> T,
    T: Future<Output=std::result::Result<U, E>>,
    E: Debug,
{
    let mut err;
    let mut i = 0u32;
    loop {
        match f().await {
            Ok(_) => return Ok(()),
            Err(e) => {
                err = e;
                i += 1;
                warn!("failed to reach neo4jthings: {:?} (attempt {})", err, i);
                if i == 10 {
                    break;
                }
                sleep(Duration::from_secs(60)).await;
            },
        }
    }
    Err(err)
}
