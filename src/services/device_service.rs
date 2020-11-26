use crate::models::mud_models::{ACEAction, ACEMatches, ACLDirection, ACLType, MUDData, ACE, ACL};
use chrono::Local;
use std::net::{IpAddr, Ipv4Addr};

pub async fn get_all_devices() -> Vec<Device> {
    // TODO: Implement SQL Logic here

    // This is mock stuff, remove me later:
    let mut mockDevices = Vec::new();
    let mud_data = MUDData {
        url: "example.com/.well-known/mud".to_string(),
        masa_url: None,
        last_update: "some_last_update".to_string(),
        systeminfo: "some_systeminfo".to_string(),
        mfg_name: "some_mfg_name".to_string(),
        model_name: "some_model_name".to_string(),
        documentation: "some_documentation".to_string(),
        expiration: Local::now(),
        acllist: vec![ACL {
            name: "some_acl_name".to_string(),
            packet_direction: ACLDirection::ToDevice,
            acl_type: ACLType::IPV6,
            ace: vec![ACE {
                name: "some_ace_name".to_string(),
                action: ACEAction::Accept,
                matches: ACEMatches {
                    protocol: None,
                    direction_initiated: None,
                    address_mask: None,
                    dnsname: None,
                    source_port: None,
                    destination_port: None,
                },
            }],
        }],
    };
    let device = Device {
        mud_url: "".to_string(),
        mac: "".to_string(),
        ip_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        mud_data: mud_data,
    };
    mockDevices.push(device);
    mockDevices
}

pub struct Device {
    pub mud_url: String,
    pub mac: String,
    pub ip_address: IpAddr,
    pub mud_data: MUDData,
}
