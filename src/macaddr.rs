use serde::{Deserialize, Serialize};

use core::fmt;
pub use macaddr::*;

/// A serializable `MacAddr` for rpc communication
///
/// @author Namib Group 3.

/// A MAC address, either in *EUI-48* or *EUI-64* format.
#[derive(Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Serialize, Deserialize)]
pub enum SerdeMacAddr {
    V6(MacAddr6),
    V8(MacAddr8),
}

impl From<MacAddr> for SerdeMacAddr {
    fn from(mac_addr: MacAddr) -> SerdeMacAddr {
        match mac_addr {
            MacAddr::V6(addr) => SerdeMacAddr::V6(addr),
            MacAddr::V8(addr) => SerdeMacAddr::V8(addr),
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<MacAddr> for SerdeMacAddr {
    fn into(self) -> MacAddr {
        match self {
            SerdeMacAddr::V6(addr) => MacAddr::V6(addr),
            SerdeMacAddr::V8(addr) => MacAddr::V8(addr),
        }
    }
}

impl fmt::Display for SerdeMacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SerdeMacAddr::V6(v6) => fmt::Display::fmt(v6, f),
            SerdeMacAddr::V8(v8) => fmt::Display::fmt(v8, f),
        }
    }
}
