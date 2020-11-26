use std::{
    convert::TryInto,
    env, net,
    net::{IpAddr, Ipv4Addr},
    num,
    os::unix::net::UnixStream,
    str::FromStr,
    time::{Duration, UNIX_EPOCH},
};

use chrono::prelude::*;
use hex;
use log::*;
use namib_shared::models::{
    DhcpEvent, DhcpLeaseInformation, DhcpLeaseVersionSpecificInformation, DhcpV4LeaseVersionSpecificInformation, DhcpV6LeaseVersionSpecificInformation, LeaseExpiryTime, MacAddress,
};

/// List of event types supported by this script.
const SUPPORTED_EVENT_TYPES: [&str; 3] = ["add", "del", "old"];

/// Error wrapper type for the dnsmasq hook script.
#[derive(Debug)]
enum DhcpDataExtractionError {
    /// The IP address that was supplied was not properly formatted.
    InvalidIpAddress(net::AddrParseError),
    /// A required argument for the script was missing.
    RequiredArgumentMissing,
    /// The supplied lease time is not a valid number.
    InvalidLeaseTime(num::ParseIntError),
    /// A required environment variable is missing.
    RequiredEnvironmentVariableMissing(env::VarError),
    /// The supplied MAC-Address is not of the correct format.
    InvalidMacAddress(hex::FromHexError),
    /// The event type this script was called with is not supported.
    UnsupportedEventType,
}

impl From<net::AddrParseError> for DhcpDataExtractionError {
    fn from(parse_error: net::AddrParseError) -> Self {
        Self::InvalidIpAddress(parse_error)
    }
}

impl From<env::VarError> for DhcpDataExtractionError {
    fn from(parse_error: env::VarError) -> Self {
        Self::RequiredEnvironmentVariableMissing(parse_error)
    }
}

impl From<hex::FromHexError> for DhcpDataExtractionError {
    fn from(parse_error: hex::FromHexError) -> Self {
        Self::InvalidMacAddress(parse_error)
    }
}

impl From<num::ParseIntError> for DhcpDataExtractionError {
    fn from(parse_error: num::ParseIntError) -> Self {
        Self::InvalidLeaseTime(parse_error)
    }
}

/// Main function for the dnsmasq hook binary.
/// This hook is called by dnsmasq (if configured correctly using the dhcp-script option) for
/// various events (e.g. a DHCP lease is created or destroyed). This binary will then check whether
/// the request should be forwarded to the enforcer and do so if appropriate.
///
/// For MUD clients, the environment variable DNSMASQ_MUD_URL should contain the MUD URL provided
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
/// DhcpEvent instance corresponding to the extracted information.
///
/// See also: http://www.thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html (option --dhcp-script) for
/// the used environment variables and command line arguments.
fn extract_dhcp_hook_data() -> Result<DhcpEvent, DhcpDataExtractionError> {
    // Get arguments and validate length of argument list.
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        return Result::Err(DhcpDataExtractionError::RequiredArgumentMissing);
    } else if !SUPPORTED_EVENT_TYPES.contains(&args[1].as_str()) {
        return Result::Err(DhcpDataExtractionError::UnsupportedEventType);
    }

    // Non version-specific parameters.
    let domain_name = std::env::var("DNSMASQ_DOMAIN").ok();
    let supplied_hostname = std::env::var("DNSMASQ_SUPPLIED_HOSTNAME").ok();
    let old_hostname = std::env::var("DNSMASQ_OLD_HOSTNAME").ok();
    let receiver_interface = std::env::var("DNSMASQ_INTERFACE").ok();
    let time_remaining: Duration = std::env::var("DNSMASQ_TIME_REMAINING")
        .map_err(DhcpDataExtractionError::from)
        .and_then(|x| x.parse::<u64>().map(Duration::from_secs).map_err(|x| x.into()))?;

    let mut user_classes = Vec::new();
    let mut uc_idx = 0;
    while let Ok(new_user_class) = std::env::var(format!("{}{}", "DNSMASQ_USER_CLASS", uc_idx.to_string())) {
        user_classes.push(new_user_class);
        uc_idx += 1;
    }

    // Parse IP address and retrieve MAC address string, extract version-specific parameters.
    let mac_address: Option<String>;
    let ip_addr = IpAddr::from_str(&args[3])?;
    let version_specific_information = match ip_addr {
        IpAddr::V4(ip_addr) => {
            mac_address = Some(args[2].replace(":", ""));
            DhcpLeaseVersionSpecificInformation::V4(DhcpV4LeaseVersionSpecificInformation { ip_addr })
        },
        IpAddr::V6(ip_addr) => {
            mac_address = std::env::var("DNSMASQ_MAC").ok().map(|v| v.replace(":", ""));

            DhcpLeaseVersionSpecificInformation::V6(DhcpV6LeaseVersionSpecificInformation { ip_addr })
        },
    };
    // Parse MAC Address from supplied string.
    // We use a match instead of the map function here to allow the decode_to_slice function to return
    // using the question mark operator in case the parsing failed.
    let mac_address = match mac_address {
        Some(mac_str) => {
            let mut mac_addr_array: MacAddress = [0; 6];
            hex::decode_to_slice(mac_str, &mut mac_addr_array)?;
            Some(mac_addr_array)
        },
        None => None,
    };

    // Lease expiry time or lease length.
    // dnsmasq provides either a UNIX timestamp of the time the DHCP lease expires or the total time
    // the lease is valid, depending on whether it was compiled with HAVE_BROKEN_RTC or not.
    let lease_expiry: LeaseExpiryTime;
    if let Ok(lease_expire_timestamp) = std::env::var("DNSMASQ_LEASE_EXPIRES") {
        match lease_expire_timestamp.parse::<i64>() {
            Ok(timestamp) => {
                lease_expiry = LeaseExpiryTime::LeaseExpiryTime(
                    Local
                        .timestamp_opt(timestamp, 0)
                        .earliest()
                        .expect("Lease expiry time cannot be represented as DateTime (overflow).")
                        .into(),
                )
            },
            Err(e) => return Result::Err(DhcpDataExtractionError::InvalidLeaseTime(e)),
        }
    } else if let Ok(lease_length) = std::env::var("DNSMASQ_LEASE_LENGTH") {
        match lease_length.parse::<u64>() {
            Ok(length) => lease_expiry = LeaseExpiryTime::LeaseLength(Duration::from_secs(length)),
            Err(e) => return Result::Err(DhcpDataExtractionError::InvalidLeaseTime(e)),
        }
    } else {
        return Result::Err(DhcpDataExtractionError::RequiredArgumentMissing);
    }

    // Construct lease information struct.
    let lease_information = DhcpLeaseInformation {
        version_specific_information,
        domain: domain_name,
        client_provided_hostname: supplied_hostname,
        old_hostname,
        user_classes,
        lease_expiry,
        time_remaining,
        receiver_interface,
        mac_address,
    };

    // Wrap in correct DhcpEvent instance and return.
    let event = match args[1].as_str() {
        "add" => DhcpEvent::LeaseAdded(lease_information),
        "del" => DhcpEvent::LeaseDestroyed(lease_information),
        "old" => DhcpEvent::ExistingLeaseUpdate(lease_information),
        // Shouldn't be possible, we checked if the event type is in SUPPORTED_EVENT_TYPES before.
        _ => unreachable!(),
    };
    Result::Ok(event)
}
