use crate::{models::Device, VERSION};
use chrono::Utc;
use lazy_static::lazy_static;
use neo4jthings_api::{
    apis::{configuration::Configuration, thing_api},
    models::{Acl, Thing},
};
use std::{env, future::Future};
use tokio::time::{sleep, Duration};

lazy_static! {
    static ref N4JT_CONFIG: Configuration = Configuration {
        basic_auth: Some((
            env::var("NEO4JTHINGS_USER").expect("NEO4JTHINGS_USER env missing"),
            Some(env::var("NEO4JTHINGS_PASS").expect("NEO4JTHINGS_PASS env missing"))
        )),
        user_agent: Some(format!("namib_mud_controller {}", VERSION)),
        ..Default::default()
    };
}

pub async fn add_device(device: Device) {
    if let Err(e) = retry_op(|| async {
        thing_api::thing_create(
            &*N4JT_CONFIG,
            Thing {
                serial: "".to_string(),
                mac_addr: device.mac_addr.unwrap().to_string(),
                ipv4_addr: if device.ip_addr.is_ipv4() {
                    device.ip_addr.to_string()
                } else {
                    "".to_string()
                },
                ipv6_addr: if device.ip_addr.is_ipv6() {
                    device.ip_addr.to_string()
                } else {
                    "".to_string()
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

pub async fn add_device_connection(device: Device, connection: String) {
    if let Err(e) = retry_op(|| async {
        thing_api::thing_connections_create(
            &*N4JT_CONFIG,
            &device.mac_addr.unwrap().to_string(), // TODO: duid
            Acl {
                name: "".to_string(),
                _type: if device.ip_addr.is_ipv4() {
                    "4t".to_string()
                } else {
                    "6t".to_string()
                },
                acl_dns: connection.clone(),
                port: vec![],
                direction_initiated: "from-device".to_string(),
                forwarding: "accept".to_string(),
                timestamp: Some(Utc::now().to_string()),
            },
        )
        .await
    })
    .await
    {
        error!("Failed to add thing connection {:?}", e)
    }
}

async fn retry_op<F, T, U, E>(mut f: F) -> std::result::Result<(), E>
where
    F: FnMut() -> T,
    T: Future<Output=std::result::Result<U, E>>,
{
    let mut err;
    let mut i = 0u32;
    loop {
        match f().await {
            Ok(_) => return Ok(()),
            Err(e) => {
                err = e;
                i += 1;
                if i == 10 {
                    break;
                }
                sleep(Duration::from_secs(60)).await;
            },
        }
    }
    Err(err)
}
