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
    pub dest_ip: std::net::IpAddr,
    pub direction: FlowDataDirection,
    pub length: u16,
    pub transport: FlowDataTransport,
    pub packet: Option<Vec<u8>>,
    pub denied: bool,

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
        denied: bool,
    ) -> FlowData {
        FlowData {
            timestamp,
            src_ip,
            dest_ip,
            direction,
            length,
            transport,
            packet,
            denied,
        }
    }
}
