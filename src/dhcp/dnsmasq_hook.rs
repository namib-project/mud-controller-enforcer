use std::{env, net, net::IpAddr, num, os::unix::net::UnixStream, str::FromStr, time::Duration};

use chrono::prelude::*;
use log::{debug, info};
use snafu::Snafu;

use namib_shared::{
    mac as macaddr,
    models::{
        DhcpEvent, DhcpLeaseInformation, DhcpLeaseVersionSpecificInformation, DhcpV4LeaseVersionSpecificInformation,
        DhcpV6LeaseVersionSpecificInformation, LeaseExpiryTime,
    },
    MacAddr,
};

enum EventType {
    Add,
    Del,
    Old,
}

impl FromStr for EventType {
    type Err = DhcpDataExtractionError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "add" => Ok(EventType::Add),
            "del" => Ok(EventType::Del),
            "old" => Ok(EventType::Old),
            _ => Err(DhcpDataExtractionError::UnsupportedEventType {
                supplied_type: s.to_owned(),
            }),
        }
    }
}

/// Error wrapper type for the dnsmasq hook script.
#[derive(Debug, Snafu)]
enum DhcpDataExtractionError {
    /// The IP address that was supplied was not properly formatted.
    #[snafu(display("Supplied IP Address \"{}\" is not valid: {}", "supplied_address", "source"))]
    InvalidIpAddress {
        supplied_address: String,
        source: net::AddrParseError,
    },
    /// A required argument for the script was missing.
    #[snafu(display("Not enough arguments supplied. Missing {} arguments.", "missing_arg_count"))]
    NotEnoughArguments { missing_arg_count: usize },
    #[snafu(display("Required argument \"{}\" is missing", "missing_arg_name"))]
    RequiredArgumentMissing { missing_arg_name: String },
    /// The supplied lease time is not a valid number.
    #[snafu(display(
        "Supplied lease time \"{}\" is not a valid number: {}",
        "supplied_lease_time",
        "source"
    ))]
    InvalidLeaseTime {
        supplied_lease_time: String,
        source: num::ParseIntError,
    },
    /// A required environment variable is missing.
    #[snafu(display("Required environment variable \"{}\" is missing", "missing_var_name"))]
    RequiredEnvironmentVariableMissing {
        missing_arg_name: String,
        source: env::VarError,
    },
    /// The supplied MAC-Address is not of the correct format.
    #[snafu(display("Supplied MAC address \"{}\" is not valid: {}", "supplied_mac", "source"))]
    InvalidMacAddress {
        supplied_mac: String,
        source: macaddr::ParseError,
    },
    /// The event type this script was called with is not supported.
    #[snafu(display("Supplied event type \"{}\" is not supported", "supplied_type"))]
    UnsupportedEventType { supplied_type: String },
}

type Result<T> = std::result::Result<T, DhcpDataExtractionError>;

/// Main function for the dnsmasq hook binary.
/// This hook is called by dnsmasq (if configured correctly using the dhcp-script option) for
/// various events (e.g. a DHCP lease is created or destroyed). This binary will then check whether
/// the request should be forwarded to the enforcer and do so if appropriate.
///
/// For MUD clients, the environment variable `DNSMASQ_MUD_URL` should contain the MUD URL provided
/// in the DHCP request when executing the binary.
fn main() {
    env_logger::init();
    // Retrieve environment variables to determine whether the DHCP request should be forwarded to
    // the enforcer.
    let dhcp_event = extract_dhcp_hook_data().expect("Error while constructing DHCP event");
    debug!("Constructed DHCP Event: {:?}", &dhcp_event);
    let socket = UnixStream::connect("/tmp/namib_dhcp.sock").expect("Failed to connect to enforcer");
    serde_json::to_writer(socket, &dhcp_event).unwrap();
    info!("DHCP Event successfully transferred to enforcer");
}

/// Extract dhcp request data from environment variables and program arguments and return a
/// `DhcpEvent` instance corresponding to the extracted information.
///
/// See also: <http://www.thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html> (option --dhcp-script) for
/// the used environment variables and command line arguments.
fn extract_dhcp_hook_data() -> Result<DhcpEvent> {
    // Get arguments and validate length of argument list.
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        return Result::Err(DhcpDataExtractionError::NotEnoughArguments {
            missing_arg_count: 4 - args.len(),
        });
    }

    // Non version-specific parameters.
    let event_type = (&args[1]).as_str().parse::<EventType>()?;
    let domain = env::var("DNSMASQ_DOMAIN").ok();
    let client_provided_hostname = env::var("DNSMASQ_SUPPLIED_HOSTNAME").ok();
    let old_hostname = env::var("DNSMASQ_OLD_HOSTNAME").ok();
    let receiver_interface = env::var("DNSMASQ_INTERFACE").ok();
    let mud_url = env::var("DNSMASQ_MUD_URL").ok();
    let time_remaining = env::var("DNSMASQ_TIME_REMAINING");
    let time_remaining: Duration = time_remaining
        .clone()
        .map_err(|e| DhcpDataExtractionError::RequiredEnvironmentVariableMissing {
            missing_arg_name: "DNSMASQ_TIME_REMAINING".to_owned(),
            source: e,
        })
        .and_then(|x| {
            x.parse::<u64>()
                .map(Duration::from_secs)
                .map_err(|e| DhcpDataExtractionError::InvalidLeaseTime {
                    // We checked that this variable
                    supplied_lease_time: time_remaining.unwrap(),
                    source: e,
                })
        })?;

    let mut user_classes = Vec::new();
    let mut uc_idx = 0;
    while let Ok(new_user_class) = env::var(format!("{}{}", "DNSMASQ_USER_CLASS", uc_idx.to_string())) {
        user_classes.push(new_user_class);
        uc_idx += 1;
    }

    // Parse IP address and retrieve MAC address string, extract version-specific parameters.
    let mac_address: Option<String>;
    let ip_addr = &args[3];
    let ip_addr = IpAddr::from_str(ip_addr).map_err(|e| DhcpDataExtractionError::InvalidIpAddress {
        supplied_address: ip_addr.clone(),
        source: e,
    })?;
    let version_specific_information = match ip_addr {
        IpAddr::V4(ip_addr) => {
            mac_address = Some(args[2].clone());
            DhcpLeaseVersionSpecificInformation::V4(DhcpV4LeaseVersionSpecificInformation { ip_addr })
        }
        IpAddr::V6(ip_addr) => {
            mac_address = env::var("DNSMASQ_MAC").ok();

            DhcpLeaseVersionSpecificInformation::V6(DhcpV6LeaseVersionSpecificInformation { ip_addr })
        }
    };
    // Parse MAC Address from supplied string.
    // We use a match instead of the map function here to allow the decode_to_slice function to return
    // using the question mark operator in case the parsing failed.
    let mac_address = match mac_address {
        Some(mac_str) => {
            let mac_addr_array: MacAddr = mac_str
                .parse::<macaddr::MacAddr>()
                .map_err(|e| DhcpDataExtractionError::InvalidMacAddress {
                    supplied_mac: mac_str,
                    source: e,
                })?
                .into();
            Some(mac_addr_array)
        }
        None => None,
    };

    // Lease expiry time or lease length.
    let lease_expiry = extract_lease_expiry_time()?;

    // Construct lease information struct.
    let lease_info = DhcpLeaseInformation {
        version_specific_information,
        domain,
        client_provided_hostname,
        old_hostname,
        user_classes,
        lease_expiry,
        time_remaining,
        receiver_interface,
        mac_address,
        mud_url,
    };

    // Wrap in correct DhcpEvent instance and return.
    Result::Ok(match event_type {
        EventType::Add => DhcpEvent::LeaseAdded {
            event_timestamp: Local::now().into(),
            lease_info,
        },
        EventType::Del => DhcpEvent::LeaseDestroyed {
            event_timestamp: Local::now().into(),
            lease_info,
        },
        EventType::Old => DhcpEvent::ExistingLeaseUpdate {
            event_timestamp: Local::now().into(),
            lease_info,
        },
    })
}

/// Extracts the lease expiry time from the appropiate environment variables.
/// Is called by `extract_dhcp_hook_data()`.
fn extract_lease_expiry_time() -> Result<LeaseExpiryTime> {
    // dnsmasq provides either a UNIX timestamp of the time the DHCP lease expires or the total time
    // the lease is valid, depending on whether it was compiled with HAVE_BROKEN_RTC or not.
    let lease_expiry: LeaseExpiryTime;
    let lease_length_var = env::var("DNSMASQ_LEASE_LENGTH");
    if let Ok(lease_expire_timestamp) = env::var("DNSMASQ_LEASE_EXPIRES") {
        match lease_expire_timestamp.parse::<i64>() {
            Ok(timestamp) => {
                lease_expiry = LeaseExpiryTime::LeaseExpiryTime(
                    Local
                        .timestamp_opt(timestamp, 0)
                        .earliest()
                        .expect("Lease expiry time cannot be represented as DateTime (overflow).")
                        .into(),
                )
            }
            Err(e) => {
                return Result::Err(DhcpDataExtractionError::InvalidLeaseTime {
                    supplied_lease_time: lease_expire_timestamp,
                    source: e,
                })
            }
        }
    } else if let Ok(lease_length) = lease_length_var {
        match lease_length.parse::<u64>() {
            Ok(length) => lease_expiry = LeaseExpiryTime::LeaseLength(Duration::from_secs(length)),
            Err(e) => {
                return Result::Err(DhcpDataExtractionError::InvalidLeaseTime {
                    supplied_lease_time: lease_length,
                    source: e,
                })
            }
        }
    } else if let Err(e) = lease_length_var {
        return Result::Err(DhcpDataExtractionError::RequiredEnvironmentVariableMissing {
            missing_arg_name: "DNSMASQ_LEASE_EXPIRES".to_owned(),
            source: e,
        });
    } else {
        // lease_length_var must either be Ok or Err.
        unreachable!();
    }
    Ok(lease_expiry)
}
