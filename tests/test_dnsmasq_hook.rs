#[cfg(feature = "dnsmasq_hook")]
mod test_dnsmasq_hook {
    use chrono::{DateTime, FixedOffset, Local, TimeZone};
    use core::time::Duration;
    use namib_shared::{
        models::{
            DhcpEvent, DhcpLeaseInformation, DhcpLeaseVersionSpecificInformation, DhcpV4LeaseVersionSpecificInformation, DhcpV6LeaseVersionSpecificInformation, Duid,
            LeaseExpiryTime,
        },
        MacAddr,
    };
    use serial_test::serial;
    use std::{
        collections::HashMap,
        env,
        ffi::OsStr,
        io::Read,
        net::{Ipv4Addr, Ipv6Addr},
        os::unix::net::UnixListener,
        path::PathBuf,
        process::{Command, Stdio},
        sync::mpsc::Sender,
        thread,
        thread::JoinHandle,
    };

    fn full_lease_info_v4() -> DhcpLeaseInformation {
        DhcpLeaseInformation {
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
        }
    }

    fn full_lease_info_v6() -> DhcpLeaseInformation {
        DhcpLeaseInformation {
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
        }
    }

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

    fn create_args_and_env_map_from_event(event: &DhcpEvent) -> (Vec<String>, HashMap<String, String>) {
        let mut args = Vec::new();
        let mut envs: HashMap<String, String> = HashMap::new();
        let lease_info = match event {
            DhcpEvent::LeaseAdded { event_timestamp, lease_info } => {
                args.push("add".to_string());
                lease_info
            },
            DhcpEvent::LeaseDestroyed { event_timestamp, lease_info } => {
                args.push("del".to_string());
                lease_info
            },
            DhcpEvent::ExistingLeaseUpdate { event_timestamp, lease_info } => {
                args.push("old".to_string());
                lease_info
            },
        };
        if let Some(receiver_interface) = &lease_info.receiver_interface {
            envs.insert("DNSMASQ_INTERFACE".to_string(), receiver_interface.clone());
        }
        envs.insert("DNSMASQ_TAGS".to_string(), lease_info.tags.join(" "));
        envs.insert("DNSMASQ_TIME_REMAINING".to_string(), lease_info.time_remaining.as_secs().to_string());
        match &lease_info.lease_expiry {
            LeaseExpiryTime::LeaseExpiryTime(datetime) => {
                envs.insert("DNSMASQ_LEASE_EXPIRES".to_string(), datetime.timestamp().to_string());
            },
            LeaseExpiryTime::LeaseLength(duration) => {
                envs.insert("DNSMASQ_LEASE_LENGTH".to_string(), duration.as_secs().to_string());
            },
        }
        if let Some(mud_url) = &lease_info.mud_url {
            envs.insert("DNSMASQ_MUD_URL".to_string(), mud_url.to_string());
        }
        if let Some(client_provided_hostname) = &lease_info.client_provided_hostname {
            envs.insert("DNSMASQ_SUPPLIED_HOSTNAME".to_string(), client_provided_hostname.to_string());
        }
        if let Some(domain) = &lease_info.domain {
            envs.insert("DNSMASQ_DOMAIN".to_string(), domain.to_string());
        }
        if let Some(old_hostname) = &lease_info.old_hostname {
            envs.insert("DNSMASQ_OLD_HOSTNAME".to_string(), old_hostname.to_string());
        }
        let mut class_num = 0;
        for user_class in &lease_info.user_classes {
            envs.insert(format!("DNSMASQ_USER_CLASS{}", class_num).to_string(), user_class.to_string());
            class_num += 1;
        }

        match &lease_info.version_specific_information {
            DhcpLeaseVersionSpecificInformation::V4(v4info) => {
                args.push(lease_info.mac_address.expect("DHCPv4 lease information must have MAC address set.").to_string());
                args.push(v4info.ip_addr.to_string());
            },
            DhcpLeaseVersionSpecificInformation::V6(v6info) => {
                if let Some(mac_addr) = &lease_info.mac_address {
                    envs.insert("DNSMASQ_MAC".to_string(), mac_addr.to_string());
                }
                args.push(v6info.duid.to_string());
                args.push(v6info.ip_addr.to_string());
            },
        };

        if let Some(hostname) = &lease_info.hostname {
            args.push(hostname.to_string());
        }

        (args, envs)
    }

    fn start_hook_script_with_event_data(event: &DhcpEvent) {
        // Unset previous environment variables
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let (args, envs) = create_args_and_env_map_from_event(event);
        result_command.args(args);
        result_command.envs(envs);
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
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v4(),
        };

        assert_script_result_equal(event);
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_add_full_ipv6() {
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v6(),
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

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_lease_length_with_broken_rtc() {
        let mut lease_info = full_lease_info_v4();
        lease_info.lease_expiry = LeaseExpiryTime::LeaseLength(Duration::from_secs(42));
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info,
        };

        assert_script_result_equal(event);
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_not_enough_arguments() {
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v4(),
        };
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let (mut args, mut envs) = create_args_and_env_map_from_event(&event);
        args.remove(3);
        args.remove(2);

        result_command.args(args).envs(envs).stdout(Stdio::null()).stderr(Stdio::null());
        // Removing a command line argument will make the program assume something else is the missing argument.
        // The error code may not be for a missing argument, but instead for an invalid value for another argument.
        assert_eq!(
            2,
            result_command
                .status()
                .expect("Error while running command.")
                .code()
                .expect("Command was terminated by a signal.")
        );
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_missing_ip_ipv4() {
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v4(),
        };
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let (mut args, mut envs) = create_args_and_env_map_from_event(&event);
        args.remove(2);

        result_command.args(args).envs(envs).stdout(Stdio::null()).stderr(Stdio::null());
        // Removing a command line argument will make the program assume something else is the missing argument.
        // The error code may not be for a missing argument, but instead for an invalid value for another argument.
        assert_ne!(
            0,
            result_command
                .status()
                .expect("Error while running command.")
                .code()
                .expect("Command was terminated by a signal.")
        );
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_missing_ip_ipv6() {
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v6(),
        };
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let (mut args, mut envs) = create_args_and_env_map_from_event(&event);
        args.remove(2);

        result_command.args(args).envs(envs).stdout(Stdio::null()).stderr(Stdio::null());
        // Removing a command line argument will make the program assume something else is the missing argument.
        // The error code may not be for a missing argument, but instead for an invalid value for another argument.
        assert_ne!(
            0,
            result_command
                .status()
                .expect("Error while running command.")
                .code()
                .expect("Command was terminated by a signal.")
        );
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_missing_event_type_ipv4() {
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v4(),
        };
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let (mut args, mut envs) = create_args_and_env_map_from_event(&event);
        args.remove(0);

        result_command.args(args).envs(envs).stdout(Stdio::null()).stderr(Stdio::null());
        // Removing a command line argument will make the program assume something else is the missing argument.
        // The error code may not be for a missing argument, but instead for an invalid value for another argument.
        assert_ne!(
            0,
            result_command
                .status()
                .expect("Error while running command.")
                .code()
                .expect("Command was terminated by a signal.")
        );
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_missing_event_type_ipv6() {
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v6(),
        };
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let (mut args, mut envs) = create_args_and_env_map_from_event(&event);
        args.remove(0);

        result_command.args(args).envs(envs).stdout(Stdio::null()).stderr(Stdio::null());
        // Removing a command line argument will make the program assume something else is the missing argument.
        // The error code may not be for a missing argument, but instead for an invalid value for another argument.
        assert_ne!(
            0,
            result_command
                .status()
                .expect("Error while running command.")
                .code()
                .expect("Command was terminated by a signal.")
        );
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_missing_mac_ipv4() {
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v4(),
        };
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let (mut args, mut envs) = create_args_and_env_map_from_event(&event);
        args.remove(1);

        result_command.args(args).envs(envs).stdout(Stdio::null()).stderr(Stdio::null());
        // Removing a command line argument will make the program assume something else is the missing argument.
        // The error code may not be for a missing argument, but instead for an invalid value for another argument.
        assert_ne!(
            0,
            result_command
                .status()
                .expect("Error while running command.")
                .code()
                .expect("Command was terminated by a signal.")
        );
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_missing_duid_ipv6() {
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v6(),
        };
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let (mut args, mut envs) = create_args_and_env_map_from_event(&event);
        args.remove(1);

        result_command.args(args).envs(envs).stdout(Stdio::null()).stderr(Stdio::null());
        // Removing a command line argument will make the program assume something else is the missing argument.
        // The error code may not be for a missing argument, but instead for an invalid value for another argument.
        assert_ne!(
            0,
            result_command
                .status()
                .expect("Error while running command.")
                .code()
                .expect("Command was terminated by a signal.")
        );
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_invalid_ip_ipv4() {
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v4(),
        };
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let (mut args, mut envs) = create_args_and_env_map_from_event(&event);
        args.push("192.168.123.256".to_string());
        args.swap_remove(2);

        result_command.args(args).envs(envs).stdout(Stdio::null()).stderr(Stdio::null());
        // Removing a command line argument will make the program assume something else is the missing argument.
        // The error code may not be for a missing argument, but instead for an invalid value for another argument.
        assert_eq!(
            4,
            result_command
                .status()
                .expect("Error while running command.")
                .code()
                .expect("Command was terminated by a signal.")
        );
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_invalid_ip_ipv6() {
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v6(),
        };
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let (mut args, mut envs) = create_args_and_env_map_from_event(&event);
        args.push("2001:0db8:85a3:0000:0000:8a2e:0370:73gg".to_string());
        args.swap_remove(2);

        result_command.args(args).envs(envs).stdout(Stdio::null()).stderr(Stdio::null());
        // Removing a command line argument will make the program assume something else is the missing argument.
        // The error code may not be for a missing argument, but instead for an invalid value for another argument.
        assert_eq!(
            4,
            result_command
                .status()
                .expect("Error while running command.")
                .code()
                .expect("Command was terminated by a signal.")
        );
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_invalid_mac_ipv4_undersize() {
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v4(),
        };
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let (mut args, mut envs) = create_args_and_env_map_from_event(&event);
        args.push("aa".to_string());
        args.swap_remove(1);

        result_command.args(args).envs(envs).stdout(Stdio::null()).stderr(Stdio::null());
        // Removing a command line argument will make the program assume something else is the missing argument.
        // The error code may not be for a missing argument, but instead for an invalid value for another argument.
        assert_eq!(
            6,
            result_command
                .status()
                .expect("Error while running command.")
                .code()
                .expect("Command was terminated by a signal.")
        );
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_invalid_mac_ipv4_oversize() {
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v4(),
        };
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let (mut args, mut envs) = create_args_and_env_map_from_event(&event);
        args.push("aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff".to_string());
        args.swap_remove(1);

        result_command.args(args).envs(envs).stdout(Stdio::null()).stderr(Stdio::null());
        // Removing a command line argument will make the program assume something else is the missing argument.
        // The error code may not be for a missing argument, but instead for an invalid value for another argument.
        assert_eq!(
            6,
            result_command
                .status()
                .expect("Error while running command.")
                .code()
                .expect("Command was terminated by a signal.")
        );
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_invalid_mac_ipv4_invalid_char() {
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v4(),
        };
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let (mut args, mut envs) = create_args_and_env_map_from_event(&event);
        args.push("aa:bb:cc:dd:ee:gg".to_string());
        args.swap_remove(1);

        result_command.args(args).envs(envs).stdout(Stdio::null()).stderr(Stdio::null());
        // Removing a command line argument will make the program assume something else is the missing argument.
        // The error code may not be for a missing argument, but instead for an invalid value for another argument.
        assert_eq!(
            6,
            result_command
                .status()
                .expect("Error while running command.")
                .code()
                .expect("Command was terminated by a signal.")
        );
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_invalid_mac_ipv6_undersize() {
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v6(),
        };
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let (mut args, mut envs) = create_args_and_env_map_from_event(&event);
        envs.insert("DNSMASQ_MAC".to_string(), "aa".to_string());

        result_command.args(args).envs(envs).stdout(Stdio::null()).stderr(Stdio::null());
        // Removing a command line argument will make the program assume something else is the missing argument.
        // The error code may not be for a missing argument, but instead for an invalid value for another argument.
        assert_eq!(
            6,
            result_command
                .status()
                .expect("Error while running command.")
                .code()
                .expect("Command was terminated by a signal.")
        );
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_invalid_mac_ipv6_oversize() {
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v6(),
        };
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let (mut args, mut envs) = create_args_and_env_map_from_event(&event);
        envs.insert("DNSMASQ_MAC".to_string(), "aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff".to_string());

        result_command.args(args).envs(envs).stdout(Stdio::null()).stderr(Stdio::null());
        // Removing a command line argument will make the program assume something else is the missing argument.
        // The error code may not be for a missing argument, but instead for an invalid value for another argument.
        assert_eq!(
            6,
            result_command
                .status()
                .expect("Error while running command.")
                .code()
                .expect("Command was terminated by a signal.")
        );
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_invalid_mac_ipv6_invalid_char() {
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v6(),
        };
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let (mut args, mut envs) = create_args_and_env_map_from_event(&event);
        envs.insert("DNSMASQ_MAC".to_string(), "aa:bb:cc:dd:ee:gg".to_string());

        result_command.args(args).envs(envs).stdout(Stdio::null()).stderr(Stdio::null());
        // Removing a command line argument will make the program assume something else is the missing argument.
        // The error code may not be for a missing argument, but instead for an invalid value for another argument.
        assert_eq!(
            6,
            result_command
                .status()
                .expect("Error while running command.")
                .code()
                .expect("Command was terminated by a signal.")
        );
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_invalid_duid_ipv6_invalid_char() {
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v6(),
        };
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let (mut args, mut envs) = create_args_and_env_map_from_event(&event);
        args.push("aa:bb:cc:dd:ee:ff:gg".to_string());
        args.swap_remove(1);

        result_command.args(args).envs(envs).stdout(Stdio::null()).stderr(Stdio::null());
        // Removing a command line argument will make the program assume something else is the missing argument.
        // The error code may not be for a missing argument, but instead for an invalid value for another argument.
        assert_eq!(
            7,
            result_command
                .status()
                .expect("Error while running command.")
                .code()
                .expect("Command was terminated by a signal.")
        );
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_invalid_duid_ipv6_undersize() {
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v6(),
        };
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let (mut args, mut envs) = create_args_and_env_map_from_event(&event);
        args.push("aa".to_string());
        args.swap_remove(1);

        result_command.args(args).envs(envs).stdout(Stdio::null()).stderr(Stdio::null());
        // Removing a command line argument will make the program assume something else is the missing argument.
        // The error code may not be for a missing argument, but instead for an invalid value for another argument.
        assert_eq!(
            7,
            result_command
                .status()
                .expect("Error while running command.")
                .code()
                .expect("Command was terminated by a signal.")
        );
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_invalid_duid_ipv6_oversize() {
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v6(),
        };
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let (mut args, mut envs) = create_args_and_env_map_from_event(&event);
        args.push("aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:aa:bb:cc".to_string());
        args.swap_remove(1);

        result_command.args(args).envs(envs).stdout(Stdio::null()).stderr(Stdio::null());
        // Removing a command line argument will make the program assume something else is the missing argument.
        // The error code may not be for a missing argument, but instead for an invalid value for another argument.
        assert_eq!(
            7,
            result_command
                .status()
                .expect("Error while running command.")
                .code()
                .expect("Command was terminated by a signal.")
        );
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_unsupported_event_type() {
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v4(),
        };
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let (mut args, mut envs) = create_args_and_env_map_from_event(&event);
        args.push("tftp".to_string());
        args.swap_remove(0);

        result_command.args(args).envs(envs).stdout(Stdio::null()).stderr(Stdio::null());
        // Removing a command line argument will make the program assume something else is the missing argument.
        // The error code may not be for a missing argument, but instead for an invalid value for another argument.
        assert_eq!(
            8,
            result_command
                .status()
                .expect("Error while running command.")
                .code()
                .expect("Command was terminated by a signal.")
        );
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_missing_time_remaining() {
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v4(),
        };
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let (mut args, mut envs) = create_args_and_env_map_from_event(&event);
        envs.remove("DNSMASQ_TIME_REMAINING");

        result_command.args(args).envs(envs).stdout(Stdio::null()).stderr(Stdio::null());
        // Removing a command line argument will make the program assume something else is the missing argument.
        // The error code may not be for a missing argument, but instead for an invalid value for another argument.
        assert_eq!(
            3,
            result_command
                .status()
                .expect("Error while running command.")
                .code()
                .expect("Command was terminated by a signal.")
        );
    }

    #[test]
    #[serial(dnsmasq_hook)]
    fn test_missing_lease_expiry() {
        let event = DhcpEvent::LeaseAdded {
            event_timestamp: DateTime::<FixedOffset>::from(Local::now()),
            lease_info: full_lease_info_v4(),
        };
        std::env::vars().filter(|(k, v)| k.starts_with("DNSMASQ_")).for_each(|(k, v)| env::remove_var(k));
        let mut result_command = Command::new(namib_dnsmasq_hook_exe());
        let (mut args, mut envs) = create_args_and_env_map_from_event(&event);
        envs.remove("DNSMASQ_LEASE_EXPIRES");

        result_command.args(args).envs(envs).stdout(Stdio::null()).stderr(Stdio::null());
        // Removing a command line argument will make the program assume something else is the missing argument.
        // The error code may not be for a missing argument, but instead for an invalid value for another argument.
        assert_eq!(
            3,
            result_command
                .status()
                .expect("Error while running command.")
                .code()
                .expect("Command was terminated by a signal.")
        );
    }
}
