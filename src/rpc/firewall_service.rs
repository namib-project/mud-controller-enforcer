use crate::{error::*, uci::*};
use namib_shared::config_firewall::*;

const CONFIG_DIR: &str = "config";

fn apply_config(uci: &mut UCI, cfg: &ConfigFirewall) -> Result<()> {
    let cfg_n = format!("firewall.namibrule_{}", cfg.hash());
    debug!("Creating rule {}", cfg_n);
    uci.set(cfg_n.as_str(), "rule")?;
    for c in cfg.to_option().iter() {
        uci.set(format!("{}.{}", cfg_n, c.0).as_str(), c.1.as_str())?;
    }
    uci.set(format!("{}.namib", cfg_n).as_str(), "1")?;
    Ok(())
}

fn apply_uci_config(uci: &mut UCI, cfg_list: Vec<ConfigFirewall>) -> Result<()> {
    delete_all_config(uci)?;
    for c in cfg_list.iter() {
        apply_config(uci, c)?;
    }
    uci.commit("firewall")?;
    Ok(())
}

pub fn apply_new_configuration(cfg_list: Vec<ConfigFirewall>) -> Result<()> {
    debug!("Applying {} configs", cfg_list.len());
    let mut uci = UCI::new()?;
    uci.set_config_dir(CONFIG_DIR)?;

    // if an error occurred roll back any changes
    if let Err(e) = apply_uci_config(&mut uci, cfg_list) {
        uci.revert("firewall")?;
        return Err(e);
    }

    #[cfg(feature = "execute_uci_commands")]
    {
        let output = restart_firewall_command();
        debug!("restart firewall: {:?}", std::str::from_utf8(&output.stderr));
    }
    Ok(())
}

fn delete_all_config(uci: &mut UCI) -> Result<()> {
    debug!("Deleting all namib configs");
    let mut index = 0;
    while uci.get(format!("firewall.@rule[{}]", index).as_str()).is_ok() {
        let is_namib = uci.get(format!("firewall.@rule[{}].namib", index).as_str()).map_or(false, |s| s == "1");

        if is_namib {
            uci.delete(format!("firewall.@rule[{}]", index).as_str())?;
            debug!("Delete entry firewall.@rule[{}]", index);
        } else {
            index += 1;
        }
    }

    Ok(())
}

#[cfg(feature = "execute_uci_commands")]
pub fn restart_firewall_command() -> std::process::Output {
    std::process::Command::new("sh")
        .arg("-c")
        .arg("service firewall restart")
        .output()
        .expect("failed to execute process")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, fs::File, io::Read};

    #[test]
    fn test_trivial_apply_config() -> Result<()> {
        init();

        File::create("tests/config/test_trivial_apply_config/firewall")?;

        let mut uci = UCI::new()?;
        uci.set_save_dir("/tmp/.uci_trivial_apply_config")?;
        uci.set_config_dir("tests/config/test_trivial_apply_config")?;

        let cfg = ConfigFirewall::new(
            RuleName::new("Regel2".to_string()),
            EnRoute::Src(EnNetwork::Lan),
            EnRoute::Des(EnNetwork::Wan),
            Protocol::tcp(),
            EnTarget::DROP,
            EnOptionalSettings::None,
        );
        apply_config(&mut uci, &cfg)?;
        uci.commit("firewall")?;

        let mut expected_string = String::new();
        let mut test_string = String::new();

        {
            let mut expected_file = File::open("tests/config/test_trivial_apply_config/expected_firewall")?;
            let mut test_file = File::open("tests/config/test_trivial_apply_config/firewall")?;

            expected_file.read_to_string(&mut expected_string)?;
            test_file.read_to_string(&mut test_string)?;
        }

        assert_eq!(test_string, expected_string);
        Ok(())
    }

    #[test]
    fn test_delete_config() -> Result<()> {
        init();

        fs::copy("tests/config/test_delete_all_config/firewall_before", "tests/config/test_delete_all_config/firewall")?;

        let mut uci = UCI::new()?;
        uci.set_save_dir("/tmp/.uci_delete_all_config")?;
        uci.set_config_dir("tests/config/test_delete_all_config")?;

        delete_all_config(&mut uci)?;

        uci.commit("firewall")?;

        let mut expected_firewall = File::open("tests/config/test_delete_all_config/expected_firewall")?;
        let mut actual_firewall = File::open("tests/config/test_delete_all_config/firewall")?;

        let mut expected_firewall_string = String::new();
        let mut actual_firewall_string = String::new();

        expected_firewall.read_to_string(&mut expected_firewall_string)?;
        actual_firewall.read_to_string(&mut actual_firewall_string)?;

        assert_eq!(expected_firewall_string, actual_firewall_string);

        Ok(())
    }

    #[test]
    fn test_apply_and_delete_config() -> Result<()> {
        init();

        fs::copy("tests/config/test_apply_and_delete/firewall_before", "tests/config/test_apply_and_delete/firewall")?;

        let mut uci = UCI::new()?;
        uci.set_save_dir("/tmp/.uci_apply_and_delete")?;
        uci.set_config_dir("tests/config/test_apply_and_delete")?;

        let cfg = ConfigFirewall::new(
            RuleName::new("Regel3".to_string()),
            EnRoute::Src(EnNetwork::Lan),
            EnRoute::Des(EnNetwork::Wan),
            Protocol::tcp(),
            EnTarget::DROP,
            EnOptionalSettings::None,
        );

        // apply the config
        apply_config(&mut uci, &cfg)?;
        uci.commit("firewall")?;

        let mut expected_firewall_string = String::new();
        let mut firewall_string = String::new();

        {
            let mut expected_firewall = File::open("tests/config/test_apply_and_delete/expected_firewall")?;
            let mut firewall = File::open("tests/config/test_apply_and_delete/firewall")?;

            expected_firewall.read_to_string(&mut expected_firewall_string)?;
            firewall.read_to_string(&mut firewall_string)?;
        }

        // check if applied config matches expected
        assert_eq!(firewall_string, expected_firewall_string);

        // now delete the applied config
        delete_all_config(&mut uci)?;
        uci.commit("firewall")?;

        let mut firewall_before_string = String::new();
        let mut firewall_string = String::new();

        {
            let mut firewall = File::open("tests/config/test_apply_and_delete/firewall")?;
            let mut firewall_before = File::open("tests/config/test_apply_and_delete/firewall_before")?;

            firewall_before.read_to_string(&mut firewall_before_string)?;
            firewall.read_to_string(&mut firewall_string)?;
        }

        assert_eq!(firewall_string, firewall_before_string);

        Ok(())
    }

    fn init() {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
            .is_test(true)
            .try_init()
            .ok();
    }
}
