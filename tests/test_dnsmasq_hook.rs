use crate::DhcpDummyListenerError::Deserialize;
use chrono::{DateTime, Duration, FixedOffset, Local, TimeZone};
use namib_shared::{
    models::{DhcpEvent, DhcpLeaseVersionSpecificInformation, LeaseExpiryTime},
    MacAddr,
};
use std::{env, io::Read, net::Ipv4Addr, os::unix::net::UnixListener, path::PathBuf, process::Command, sync::mpsc::Sender, thread, thread::JoinHandle};

// Helper functions for finding the dnsmasq hook binary.
// Taken from https://github.com/rust-lang/cargo/blob/7fa132c7272fb9faca365c1d350e8e3c4c0d45e9/tests/cargotest/support/mod.rs#L316-L333
// as suggested by a forum post https://users.rust-lang.org/t/integration-test-bin-itself/4769/3
// to find built binaries for integration testing.
fn cargo_dir() -> PathBuf {
    env::var_os("CARGO_BIN_PATH")
        .map(PathBuf::from)
        .or_else(|| {
            env::current_exe().ok().map(|mut path| {
                path.pop();
                if path.ends_with("deps") {
                    path.pop();
                }
                path
            })
        })
        .unwrap_or_else(|| panic!("CARGO_BIN_PATH wasn't set. Cannot continue running test"))
}

fn namib_dnsmasq_hook_exe() -> PathBuf {
    cargo_dir().join(format!("namib_dnsmasq_hook{}", env::consts::EXE_SUFFIX))
}

#[derive(Debug)]
enum DhcpDummyListenerError {
    Io(std::io::Error),
    Deserialize(serde_json::Error),
}

impl From<serde_json::Error> for DhcpDummyListenerError {
    fn from(e: serde_json::Error) -> Self {
        DhcpDummyListenerError::Deserialize(e)
    }
}

impl From<std::io::Error> for DhcpDummyListenerError {
    fn from(e: std::io::Error) -> Self {
        DhcpDummyListenerError::Io(e)
    }
}

type DhcpDummyListenerResult = Result<DhcpEvent, DhcpDummyListenerError>;

fn event_listener_dummy() -> DhcpDummyListenerResult {
    match std::fs::remove_file("/tmp/namib_dhcp.sock") {
        Ok(_) => Ok(()),
        Err(err) => match err.kind() {
            std::io::ErrorKind::NotFound => Ok(()),
            e => Err(err),
        },
    }?;
    let listener = UnixListener::bind("/tmp/namib_dhcp.sock")?;
    let mut conn = listener.accept()?.0;
    let mut inc_data = Vec::new();
    conn.read_to_end(&mut inc_data).unwrap();
    Ok(serde_json::from_slice::<DhcpEvent>(inc_data.as_slice())?)
}

fn event_listener_thread() -> JoinHandle<DhcpDummyListenerResult> {
    thread::spawn(|| event_listener_dummy())
}

#[test]
fn test_successful_ipv4() {
    let dhcp_listener_result = event_listener_thread();

    env::set_var("DNSMASQ_INTERFACE", "eth0");
    env::set_var("DNSMASQ_TAGS", "lan");
    env::set_var("DNSMASQ_TIME_REMAINING", "43200");
    env::set_var("DNSMASQ_LEASE_EXPIRES", "1605596290");
    env::set_var("DNSMASQ_MUD_URL", "https://iotanalytics.unsw.edu.au/mud/amazonEchoMud.json");
    env::set_var("DNSMASQ_LOG_DHCP", "1");
    env::set_var("DNSMASQ_REQUESTED_OPTIONS", "1,28,2,3,15,6,119,12,44,47,26,121,42");
    env::set_var("DNSMASQ_SUPPLIED_HOSTNAME", "64cb69b4591c");

    Command::new(namib_dnsmasq_hook_exe())
        .arg("add")
        .arg("aa:bb:cc:dd:ee:ff")
        .arg("192.168.1.15")
        .arg("hostname")
        .output()
        .expect("Error while running command.");

    let event = dhcp_listener_result.join().expect("Event listener thread paniced!").expect("Did not receive DHCP event!");
    match event {
        DhcpEvent::LeaseAdded { event_timestamp, lease_info } => {
            let actual_mac: Option<MacAddr> = Some("aa:bb:cc:dd:ee:ff".parse::<macaddr::MacAddr>().unwrap().into());
            assert_eq!(lease_info.mac_address, actual_mac);
            assert_eq!(lease_info.client_provided_hostname, Some("64cb69b4591c".to_string()));
            assert_eq!(lease_info.mud_url, Some("https://iotanalytics.unsw.edu.au/mud/amazonEchoMud.json".to_string()));
            assert_eq!(lease_info.old_hostname, None);
            assert_eq!(lease_info.receiver_interface, Some("eth0".to_string()));
            assert_eq!(lease_info.time_remaining, std::time::Duration::from_secs(43200));
            assert_eq!(lease_info.user_classes, Vec::<String>::new());
            match lease_info.version_specific_information {
                DhcpLeaseVersionSpecificInformation::V4(vsi) => {
                    assert_eq!(vsi.ip_addr, Ipv4Addr::new(192, 168, 1, 15));
                },
                _ => panic!("IP address has been converted to wrong type!"),
            }
            if let LeaseExpiryTime::LeaseExpiryTime(datetime) = lease_info.lease_expiry {
                assert_eq!(
                    datetime,
                    DateTime::<FixedOffset>::from(
                        Local
                            .timestamp_opt(1605596290, 0)
                            .earliest()
                            .expect("Lease expiry time cannot be represented as DateTime (overflow).")
                    )
                );
            } else {
                panic!("Lease expiry timestamp was not provided!");
            }
        },
        _ => panic!("Received DHCP event is of wrong type."),
    }
}
