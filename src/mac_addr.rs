use macaddr::{MacAddr6, MacAddr8};
use serde::{Deserialize, Serialize};

use core::fmt;
pub use macaddr;

/// A MAC address, either in *EUI-48* or *EUI-64* format.
#[derive(Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Serialize, Deserialize)]
pub enum MacAddr {
    V6(MacAddr6),
    V8(MacAddr8),
}

impl From<macaddr::MacAddr> for MacAddr {
    fn from(mac_addr: macaddr::MacAddr) -> MacAddr {
        match mac_addr {
            macaddr::MacAddr::V6(addr) => MacAddr::V6(addr),
            macaddr::MacAddr::V8(addr) => MacAddr::V8(addr),
        }
    }
}

impl Into<macaddr::MacAddr> for MacAddr {
    fn into(self) -> macaddr::MacAddr {
        match self {
            MacAddr::V6(addr) => macaddr::MacAddr::V6(addr),
            MacAddr::V8(addr) => macaddr::MacAddr::V8(addr),
        }
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MacAddr::V6(v6) => fmt::Display::fmt(v6, f),
            MacAddr::V8(v8) => fmt::Display::fmt(v8, f),
        }
    }
}
