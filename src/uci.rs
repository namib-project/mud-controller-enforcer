#[cfg(not(feature = "uci"))]
pub use mock::*;
#[cfg(feature = "uci")]
pub use rust_uci::*;

#[cfg(not(feature = "uci"))]
#[allow(clippy::unused_self)]
mod mock {

    use crate::error::{self, Result};

    pub struct Uci {}

    impl Uci {
        pub fn new() -> Result<Self> {
            Ok(Self {})
        }

        pub fn set_config_dir(&mut self, config_dir: &str) -> Result<()> {
            debug!("set_config_dir {}", config_dir);
            Ok(())
        }

        pub fn set_save_dir(&mut self, save_dir: &str) -> Result<()> {
            debug!("set_save_dir {}", save_dir);
            Ok(())
        }

        pub fn revert(&mut self, package: &str) -> Result<()> {
            debug!("revert {}", package);
            Ok(())
        }

        pub fn delete(&mut self, key: &str) -> Result<()> {
            debug!("delete {}", key);
            Ok(())
        }

        pub fn get(&mut self, key: &str) -> Result<String> {
            debug!("get {}", key);
            error::NoneError {}.fail()
        }

        pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
            debug!("set {}={}", key, value);
            Ok(())
        }

        pub fn commit(&mut self, package: &str) -> Result<()> {
            debug!("commit {}", package);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, fs::File, io::Read};

    use super::*;
    use crate::error::Result;

    fn init() -> Result<Uci> {
        let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
            .is_test(true)
            .try_init();

        let mut uci = Uci::new()?;
        uci.set_config_dir("tests/config")?;
        uci.set_save_dir("/tmp/.uci_tests")?;

        Ok(uci)
    }

    #[test]
    fn test_reading_key() -> Result<()> {
        let mut uci = init()?;

        assert_eq!(uci.get("network.wan")?, "interface");
        assert_eq!(uci.get("network.@interface[0]")?, "interface");
        assert_eq!(uci.get("network.a")?, "alias");
        assert_eq!(uci.get("network.@alias[-1]")?, "alias");
        assert_eq!(uci.get("network.wan.proto")?, "dhcp");
        assert_eq!(uci.get("network.@interface[-1].proto")?, "dhcp");
        assert_eq!(uci.get("network.lan.proto")?, "static");
        assert_eq!(uci.get("network.@interface[0].proto")?, "static");
        assert_eq!(uci.get("broken.a").is_err(), true);
        assert_eq!(uci.get("broken.a.b").is_err(), true);
        assert_eq!(uci.get("inexistant.c").is_err(), true);
        assert_eq!(uci.get("inexistant.c.d").is_err(), true);
        Ok(())
    }

    #[test]
    fn test_writing_key() -> Result<()> {
        let mut uci = init()?;

        File::create("tests/config/new_network")?;

        uci.set("new_network.a", "alias")?;
        uci.set("new_network.a.interface", "lan")?;
        uci.set("new_network.b", "alias")?;
        uci.set("new_network.b.interface", "lan")?;
        uci.set("new_network.lan", "interface")?;
        uci.set("new_network.lan.proto", "static")?;
        uci.set("new_network.lan.ifname", "eth0")?;
        uci.set("new_network.lan.test", "123")?;
        uci.set("new_network.lan.enabled", "off")?;
        uci.set("new_network.lan.ipaddr", "2.3.4.5")?;
        uci.set("new_network.wan", "interface")?;
        uci.set("new_network.wan.proto", "dhcp")?;
        uci.set("new_network.wan.ifname", "eth1")?;
        uci.set("new_network.wan.enabled", "on")?;
        uci.set("new_network.wan.aliases", "c d")?;
        uci.set("new_network.c", "alias")?;
        uci.set("new_network.c.interface", "wan")?;
        uci.set("new_network.d", "alias")?;
        uci.set("new_network.d.interface", "wan")?;
        uci.commit("new_network")?;

        let mut file = File::open("tests/config/new_network")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let mut file = File::open("tests/config/network")?;
        let mut actual_contents = String::new();
        file.read_to_string(&mut actual_contents)?;

        fs::remove_file("tests/config/new_network")?;

        assert_eq!(contents, actual_contents);
        Ok(())
    }

    #[test]
    fn test_delete() -> Result<()> {
        let mut uci = init()?;

        assert_eq!(uci.get("network.wan.proto")?, "dhcp");
        assert_eq!(uci.get("network.wan.ifname")?, "eth1");
        uci.delete("network.wan")?;
        assert_eq!(uci.get("network.wan.proto").is_err(), true);
        assert_eq!(uci.get("network.wan.ifname").is_err(), true);
        uci.revert("network")?;
        assert_eq!(uci.get("network.wan.proto")?, "dhcp");
        assert_eq!(uci.get("network.wan.ifname")?, "eth1");
        Ok(())
    }
}
