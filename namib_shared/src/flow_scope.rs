use crate::macaddr::SerdeMacAddr;
use macaddr::MacAddr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum LogGroup {
    FullFromDevice = 0,
    FullToDevice,
    HeadersOnlyFromDevice,
    HeadersOnlyToDevice,
    DenialsFromDevice,
    DenialsToDevice,
}

impl From<LogGroup> for u32 {
    fn from(group: LogGroup) -> u32 {
        group as u32
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum FlowDataDirection {
    FromDevice,
    ToDevice,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlowDataTcp {
    pub sport: u16,
    pub dport: u16,
    psh: bool,
    ece: bool,
}

impl FlowDataTcp {
    pub fn new(src_port: u16, dst_port: u16, psh: bool, ece: bool) -> FlowDataTcp {
        FlowDataTcp {
            sport: src_port,
            dport: dst_port,
            psh,
            ece,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlowDataUdp {
    pub sport: u16,
    pub dport: u16,
}

impl FlowDataUdp {
    pub fn new(src_port: u16, dst_port: u16) -> FlowDataUdp {
        FlowDataUdp {
            sport: src_port,
            dport: dst_port,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FlowDataTransport {
    None,
    Tcp(FlowDataTcp),
    Udp(FlowDataUdp),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlowData {
    pub timestamp: Option<std::time::SystemTime>,
    pub src_ip: std::net::IpAddr,
    pub src_mac: Option<SerdeMacAddr>,
    pub dest_ip: std::net::IpAddr,
    pub dest_mac: Option<SerdeMacAddr>,
    pub direction: FlowDataDirection,
    pub length: u16,
    pub transport: FlowDataTransport,
    pub packet: Option<Vec<u8>>,
    pub denied: bool,

}

impl FlowData {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        timestamp: Option<std::time::SystemTime>,
        src_ip: std::net::IpAddr,
        src_mac: Option<MacAddr>,
        dest_ip: std::net::IpAddr,
        dest_mac: Option<MacAddr>,
        direction: FlowDataDirection,
        length: u16,
        transport: FlowDataTransport,
        packet: Option<Vec<u8>>,
        denied: bool,
    ) -> FlowData {
        FlowData {
            timestamp,
            src_ip,
            src_mac: src_mac.map(SerdeMacAddr::from),
            dest_ip,
            dest_mac: dest_mac.map(SerdeMacAddr::from),
            direction,
            length,
            transport,
            packet,
            denied,
        }
    }
}
