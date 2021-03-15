use crate::{error::Result, uci::Uci};
use std::net::SocketAddr;

pub(crate) fn apply_secure_name_config(secure_name: &str, controller_addr: SocketAddr) -> Result<()> {
    let mut uci = Uci::new()?;

    uci.set("dhcp.namib", "domain")?;
    uci.set("dhcp.namib.name", secure_name)?;
    uci.set("dhcp.namib.ip", &controller_addr.ip().to_string())?;
    let return_val = uci.commit("dhcp");
    if let Err(_e) = &return_val {
        if let Err(revert_error) = uci.revert("dhcp") {
            error!("Error while reverting UCI configuration: {:?}", revert_error);
        }
    }
    return_val
}
