use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum LogGroup {
    FullFromDevice = 0,
    FullToDevice,
    HeadersOnlyFromDevice,
    HeadersOnlyToDevice,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct FlowDataTcp {
    sport: u16,
    dport: u16,
    psh: bool,
    ece: bool,
}

impl FlowDataTcp {
    pub fn new(sport: u16, dport: u16, psh: bool, ece: bool) -> FlowDataTcp {
        FlowDataTcp { sport, dport, psh, ece }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FlowDataUdp {
    sport: u16,
    dport: u16,
}

impl FlowDataUdp {
    pub fn new(sport: u16, dport: u16) -> FlowDataUdp {
        FlowDataUdp { sport, dport }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum FlowDataTransport {
    None,
    Tcp(FlowDataTcp),
    Udp(FlowDataUdp),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FlowData {
    timestamp: Option<std::time::SystemTime>,
    src_ip: std::net::IpAddr,
    dest_ip: std::net::IpAddr,
    direction: FlowDataDirection,
    length: u16,
    transport: FlowDataTransport,
    packet: Option<Vec<u8>>,
}

impl FlowData {
    pub fn new(
        timestamp: Option<std::time::SystemTime>,
        src_ip: std::net::IpAddr,
        dest_ip: std::net::IpAddr,
        direction: FlowDataDirection,
        length: u16,
        transport: FlowDataTransport,
        packet: Option<Vec<u8>>,
    ) -> FlowData {
        FlowData {
            timestamp,
            src_ip,
            dest_ip,
            direction,
            length,
            transport,
            packet,
        }
    }
}
