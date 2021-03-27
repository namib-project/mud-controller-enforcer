use crate::{error::Result, services::is_system_mode, uci::Uci};
use std::net::SocketAddr;

/// The folder where the configuration file should be stored.
const CONFIG_DIR: &str = "config";
const SAVE_DIR: &str = "/tmp/.uci_namib";

pub(crate) fn apply_secure_name_config(secure_name: &str, controller_addr: SocketAddr) -> Result<()> {
    let mut uci = Uci::new()?;
    if !is_system_mode() {
        uci.set_config_dir(CONFIG_DIR)?;
        uci.set_save_dir(SAVE_DIR)?;
    }

    if let Err(err) = (|| {
        uci.set("dhcp.namib", "domain")?;
        uci.set("dhcp.namib.name", secure_name)?;
        uci.set("dhcp.namib.ip", &controller_addr.ip().to_string())?;
        uci.commit("dhcp")
    })() {
        error!("Failed to apply namib domain name {:?}", err);
        if let Err(revert_error) = uci.revert("dhcp") {
            error!("Error while reverting UCI configuration: {:?}", revert_error);
        }
        Err(err.into())
    } else {
        Ok(())
    }
}
