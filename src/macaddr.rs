use serde::{Deserialize, Serialize};

use core::fmt;
pub use macaddr as mac;

/// A MAC address, either in *EUI-48* or *EUI-64* format.
#[derive(Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Serialize, Deserialize)]
pub enum MacAddr {
    V6(mac::MacAddr6),
    V8(mac::MacAddr8),
}

impl From<mac::MacAddr> for MacAddr {
    fn from(mac_addr: mac::MacAddr) -> MacAddr {
        match mac_addr {
            mac::MacAddr::V6(addr) => MacAddr::V6(addr),
            mac::MacAddr::V8(addr) => MacAddr::V8(addr),
        }
    }
}

// We need to implement Into over From here, because we have neither implemented the Into trait
// nor the mac::MacAddr struct.
#[allow(clippy::from_over_into)]
impl Into<mac::MacAddr> for MacAddr {
    fn into(self) -> mac::MacAddr {
        match self {
            MacAddr::V6(addr) => mac::MacAddr::V6(addr),
            MacAddr::V8(addr) => mac::MacAddr::V8(addr),
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
