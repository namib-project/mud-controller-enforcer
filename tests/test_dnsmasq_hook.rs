#[cfg(feature = "dnsmasq_hook")]
mod test_dnsmasq_hook {
    use chrono::{DateTime, Duration, FixedOffset, Local, TimeZone};
    use namib_shared::{
        models::{
            DhcpEvent, DhcpLeaseInformation, DhcpLeaseVersionSpecificInformation, DhcpV4LeaseVersionSpecificInformation, DhcpV6LeaseVersionSpecificInformation, Duid,
            LeaseExpiryTime,
        },
        MacAddr,
    };
    use serial_test::serial;
    use std::{
        env,
        io::Read,
        net::{Ipv4Addr, Ipv6Addr},
        os::unix::net::UnixListener,
        path::PathBuf,
        process::Command,
        sync::mpsc::Sender,
        thread,
        thread::JoinHandle,
    };

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

    fn unset_environment_variables() {}

    fn start_hook_script_with_event_data(event: &DhcpEvent) {
        // Unset previous environment variables
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let lease_info = match event {
            DhcpEvent::LeaseAdded { event_timestamp, lease_info } => {
                result_command.arg("add");
                lease_info
            },
            DhcpEvent::LeaseDestroyed { event_timestamp, lease_info } => {
                result_command.arg("del");
                lease_info
            },
            DhcpEvent::ExistingLeaseUpdate { event_timestamp, lease_info } => {
                result_command.arg("old");
                lease_info
            },
        };
        if let Some(receiver_interface) = &lease_info.receiver_interface {
            env::set_var("DNSMASQ_INTERFACE", receiver_interface);
        }
        env::set_var("DNSMASQ_TAGS", lease_info.tags.join(" "));
        env::set_var("DNSMASQ_TIME_REMAINING", lease_info.time_remaining.as_secs().to_string());
        match &lease_info.lease_expiry {
            LeaseExpiryTime::LeaseExpiryTime(datetime) => {
                env::set_var("DNSMASQ_LEASE_EXPIRES", datetime.timestamp().to_string());
            },
            LeaseExpiryTime::LeaseLength(duration) => {
                env::set_var("DNSMASQ_LEASE_LENGTH", duration.as_secs().to_string());
            },
        }
        if let Some(mud_url) = &lease_info.mud_url {
            env::set_var("DNSMASQ_MUD_URL", mud_url);
        }
        if let Some(client_provided_hostname) = &lease_info.client_provided_hostname {
            env::set_var("DNSMASQ_SUPPLIED_HOSTNAME", client_provided_hostname);
        }
        if let Some(domain) = &lease_info.domain {
            env::set_var("DNSMASQ_DOMAIN", domain);
        }
        if let Some(old_hostname) = &lease_info.old_hostname {
            env::set_var("DNSMASQ_OLD_HOSTNAME", old_hostname);
        }
        let mut class_num = 0;
        for user_class in &lease_info.user_classes {
            env::set_var(format!("DNSMASQ_USER_CLASS{}", class_num), user_class);
            class_num += 1;
        }

        match &lease_info.version_specific_information {
            DhcpLeaseVersionSpecificInformation::V4(v4info) => {
                result_command.arg(lease_info.mac_address.expect("DHCPv4 lease information must have MAC address set.").to_string());
                result_command.arg(v4info.ip_addr.to_string());
            },
            DhcpLeaseVersionSpecificInformation::V6(v6info) => {
                if let Some(mac_addr) = &lease_info.mac_address {
                    env::set_var("DNSMASQ_MAC", mac_addr.to_string())
                }
                result_command.arg(v6info.duid.to_string());
                result_command.arg(v6info.ip_addr.to_string());
            },
        };

        if let Some(hostname) = &lease_info.hostname {
            result_command.arg(hostname);
        }

        result_command.output().expect("Error while running command.");
    }

    fn assert_script_result_equal(event: DhcpEvent) {
        let dhcp_listener_result = event_listener_thread();
        let actual_event_type;
        start_hook_script_with_event_data(&event);
        let actual_lease_info = match event {
            DhcpEvent::LeaseAdded {
                event_timestamp: _,
                lease_info: actual_lease_info,
            } => {
                actual_event_type = "add";
                actual_lease_info
            },
            DhcpEvent::ExistingLeaseUpdate {
                event_timestamp: _,
                lease_info: actual_lease_info,
            } => {
                actual_event_type = "old";
                actual_lease_info
            },
            DhcpEvent::LeaseDestroyed {
                event_timestamp: _,
                lease_info: actual_lease_info,
            } => {
                actual_event_type = "del";
                actual_lease_info
            },
        };
        let received_event = dhcp_listener_result.join().expect("Event listener thread paniced!").expect("Did not receive DHCP event!");
        let received_event_type;
        let received_lease_info = match received_event {
            DhcpEvent::LeaseAdded {
                event_timestamp: _,
                lease_info: received_lease_info,
            } => {
                received_event_type = "add";
                received_lease_info
            },
            DhcpEvent::ExistingLeaseUpdate {
                event_timestamp: _,
                lease_info: received_lease_info,
            } => {
                received_event_type = "old";
                received_lease_info
            },
            DhcpEvent::LeaseDestroyed {
                event_timestamp: _,
                lease_info: received_lease_info,
            } => {
                received_event_type = "del";
                received_lease_info
            },
        };
        assert_eq!(actual_event_type, received_event_type);
        assert_eq!(actual_lease_info, received_lease_info);
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_add_full_ipv4() {
        let lease_info = DhcpLeaseInformation {
            version_specific_information: DhcpLeaseVersionSpecificInformation::V4(DhcpV4LeaseVersionSpecificInformation {
                ip_addr: Ipv4Addr::new(192, 168, 1, 15),
            }),
            domain: Some("64cb69b4591c.domain.example".to_string()),
            client_provided_hostname: Some("64cb69b4591c".to_string()),
            old_hostname: None,
            user_classes: vec!["testclass1".to_string(), "testclass2".to_string()],
            lease_expiry: LeaseExpiryTime::LeaseExpiryTime(Local.timestamp_opt(1605596290, 0).earliest().unwrap().into()),
            time_remaining: std::time::Duration::from_secs(43200),
            receiver_interface: Some("eth0".to_string()),
            mac_address: Some("aa:bb:cc:dd:ee:ff".parse::<macaddr::MacAddr>().unwrap().into()),
            mud_url: Some("https://iotanalytics.unsw.edu.au/mud/amazonEchoMud.json".to_string()),
            tags: vec!["lan".to_string(), "lan2".to_string()],
            hostname: Some("actual_hostname".to_string()),
        };

        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: lease_info.clone(),
        };

        assert_script_result_equal(event);
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_add_full_ipv6() {
        let lease_info = DhcpLeaseInformation {
            version_specific_information: DhcpLeaseVersionSpecificInformation::V6(DhcpV6LeaseVersionSpecificInformation {
                ip_addr: Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0000, 0000, 0x8a2e, 0x0370, 0x7334),
                duid: Duid::Uuid(Vec::from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])),
            }),
            domain: Some("64cb69b4591c.domain.example".to_string()),
            client_provided_hostname: Some("64cb69b4591c".to_string()),
            old_hostname: None,
            user_classes: vec!["testclass1".to_string(), "testclass2".to_string()],
            lease_expiry: LeaseExpiryTime::LeaseExpiryTime(Local.timestamp_opt(1605596290, 0).earliest().unwrap().into()),
            time_remaining: std::time::Duration::from_secs(43200),
            receiver_interface: Some("eth0".to_string()),
            mac_address: Some("aa:bb:cc:dd:ee:ff".parse::<macaddr::MacAddr>().unwrap().into()),
            mud_url: Some("https://iotanalytics.unsw.edu.au/mud/amazonEchoMud.json".to_string()),
            tags: vec!["lan".to_string(), "lan2".to_string()],
            hostname: Some("actual_hostname".to_string()),
        };

        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: lease_info.clone(),
        };

        assert_script_result_equal(event);
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_add_minimal_ipv4() {
        let lease_info = DhcpLeaseInformation {
            version_specific_information: DhcpLeaseVersionSpecificInformation::V4(DhcpV4LeaseVersionSpecificInformation {
                ip_addr: Ipv4Addr::new(192, 168, 1, 16),
            }),
            domain: None,
            client_provided_hostname: None,
            old_hostname: None,
            user_classes: vec![],
            lease_expiry: LeaseExpiryTime::LeaseExpiryTime(Local.timestamp_opt(1605596290, 0).earliest().unwrap().into()),
            time_remaining: std::time::Duration::from_secs(43200),
            receiver_interface: None,
            mac_address: Some("aa:bb:cc:dd:ee:ff".parse::<macaddr::MacAddr>().unwrap().into()),
            mud_url: None,
            tags: vec![],
            hostname: None,
        };

        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: lease_info.clone(),
        };

        assert_script_result_equal(event);
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_add_minimal_ipv6() {
        let lease_info = DhcpLeaseInformation {
            version_specific_information: DhcpLeaseVersionSpecificInformation::V6(DhcpV6LeaseVersionSpecificInformation {
                ip_addr: Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0000, 0000, 0x8a2e, 0x0370, 0x7335),
                duid: Duid::Uuid(Vec::from([0xaa, 0xbb, 0xcc, 0xdd, 0xef, 0xff])),
            }),
            domain: None,
            client_provided_hostname: None,
            old_hostname: None,
            user_classes: vec![],
            lease_expiry: LeaseExpiryTime::LeaseExpiryTime(Local.timestamp_opt(1605596290, 0).earliest().unwrap().into()),
            time_remaining: std::time::Duration::from_secs(43200),
            receiver_interface: None,
            mac_address: None,
            mud_url: None,
            tags: vec![],
            hostname: None,
        };

        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: lease_info.clone(),
        };

        assert_script_result_equal(event);
    }
}
