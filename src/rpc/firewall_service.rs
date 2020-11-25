use crate::{error::*, uci::*};
use namib_shared::config_firewall::*;
use std::process::{Command, Output};

//TODO Test für löschen unserer Rules. Attribute Option Namib prüfen, Liste von Regeln anwenden (mit format! (einzigartiger name)) (flash) und commit.

const CONFIG_DIR: &str = "config";

pub fn create_query(cfg: ConfigFirewall) {
    let command_as_string = create_command(cfg.to_vector_string());

    #[cfg(feature = "execute_uci_commands")]
    {
        let output = run_command(command_as_string);

        let s: String = output.stdout.iter().map(|c| *c as char).collect();
        let e: String = output.stderr.iter().map(|c| *c as char).collect();

        commit_firewall_command();
        restart_firewall_command();
        println!("Success: {}", s);
        println!("Error: {}", e);
    }
}

pub fn apply_config(cfg: ConfigFirewall) -> Result<()> {
    let mut uci = UCI::new()?;
    uci.set_config_dir(CONFIG_DIR)?;
    let cfg_n = format!("firewall.namibrule_{}", cfg.hash());
    uci.set(cfg_n.as_str(), "rule")?;
    for c in cfg.to_option().iter() {
        uci.set(format!("{}.{}", cfg_n, c.0).as_str(), c.1.as_str())?;
    }
    uci.set(format!("{}.namib", cfg_n).as_str(), format!("namibrule_{}", cfg.hash().as_str()).as_str());
    uci.commit("firewall")?;
    Ok(())
}

pub fn apply_config_list(cfg_list: Vec<ConfigFirewall>) -> Result<()> {
    for c in cfg_list.iter() {
        apply_config(c.clone())?;
    }
    Ok(())
}

pub fn delete_config(identifier: &str) -> Result<()> {
    let mut uci = UCI::new()?;
    uci.set_config_dir(CONFIG_DIR)?;
    uci.delete(identifier)?;
    uci.commit("firewall")?;
    Ok(())
}

pub fn flash_config() -> Result<()> {
    let mut uci = UCI::new()?;
    uci.set_config_dir(CONFIG_DIR)?;
    let end_rule = format!("firewall.{}", uci.get("firewall.@rule[-1].namib")?);
    println!("{}", end_rule);
    let mut i = 0;
    let mut iter_str = format!("firewall.{}", uci.get(format!("firewall.@rule[{}].namib", i).as_str())?);
    while !iter_str.eq(&end_rule) {
        uci.delete(iter_str.as_str())?;
        println!("{}", iter_str);
        i += 1;
        iter_str = format!("firewall.{}", uci.get(format!("firewall.@rule[{}].namib", i).as_str())?);
    }
    uci.delete(end_rule.as_str())?;
    uci.commit("firewall")?;
    Ok(())
}

fn run_command(command_as_string: String) -> Output {
    let u = if cfg!(target_os = "windows") {
        Command::new("cmd").args(&["/C", command_as_string.as_str()]).output().expect("failed to execute process")
    } else {
        Command::new("sh").arg("-c").arg(command_as_string.as_str()).output().expect("failed to execute process")
    };
    u
}

fn create_command(vec: Vec<String>) -> String {
    let mut start_command: String = "uci add firewall ".to_string() + vec[0].as_str();
    let mutable_command: String = "uci set firewall.@rule[-1].".to_string();
    for i in 1..vec.len() {
        start_command.push_str(" && ");
        start_command.push_str(&mutable_command);
        start_command.push_str(vec[i].as_str());
    }
    debug!("{}::{:?}", start_command, vec);
    start_command
}

#[cfg(feature = "execute_uci_commands")]
fn commit_firewall_command() -> Output {
    let output = if cfg!(target_os = "windows") {
        Command::new("cmd").args(&["/C", "uci commit firewall"]).output().expect("failed to execute process")
    } else {
        Command::new("sh").arg("-c").arg("uci commit firewall").output().expect("failed to execute process")
    };
    output
}

#[cfg(feature = "execute_uci_commands")]
fn restart_firewall_command() -> Output {
    let output = if cfg!(target_os = "windows") {
        Command::new("cmd").args(&["/C", "service firewall restart"]).output().expect("failed to execute process")
    } else {
        Command::new("sh").arg("-c").arg("service firewall restart").output().expect("failed to execute process")
    };
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{error::*, uci::*};
    use std::{
        collections::hash_map::DefaultHasher,
        fs::File,
        io::{Read, Seek},
    };

    #[test]
    fn test_trivial_apply_config() -> Result<()> {
        init();
        let mut uci = UCI::new()?;
        uci.set_config_dir("config")?;
        let cfg = ConfigFirewall::new(
            RuleName::new("Regel2".to_string()),
            EnRoute::Src(EnNetwork::Lan),
            EnRoute::Des(EnNetwork::Wan),
            Protocol::tcp(),
            EnTarget::DROP,
            EnOptionalSettings::None,
        );
        apply_config(cfg.clone())?;

        let mut expected_string = String::new();
        let mut test_string = String::new();

        let mut expected_file = File::open("tests/config/test_trivial_apply_config/expected_firewall")?;
        let mut test_file = File::open("config/firewall")?;

        expected_file.read_to_string(&mut expected_string)?;
        test_file.read_to_string(&mut test_string)?;

        println!("test: {} \n expected: {}", test_string, expected_string);

        assert_eq!(test_string, expected_string);
        Ok(())
    }

    #[test]
    fn test_trivial_delete_config() -> Result<()> {
        init();

        let mut uci = UCI::new()?;
        uci.set_config_dir("config")?;

        let cfg = ConfigFirewall::new(
            RuleName::new("Regel3".to_string()),
            EnRoute::Src(EnNetwork::Lan),
            EnRoute::Des(EnNetwork::Wan),
            Protocol::tcp(),
            EnTarget::DROP,
            EnOptionalSettings::None,
        );
        apply_config(cfg.clone())?;

        let mut expected_firewall = File::open("tests/config/test_trivial_delete_config/expected_firewall")?;
        let mut firewall_before = File::open("tests/config/test_trivial_delete_config/firewall_before")?;
        let mut firewall = File::open("config/firewall")?;

        let mut expected_firewall_string = String::new();
        let mut firewall_before_string = String::new();
        let mut firewall_string = String::new();

        expected_firewall.read_to_string(&mut expected_firewall_string)?;
        firewall_before.read_to_string(&mut firewall_before_string)?;
        firewall.read_to_string(&mut firewall_string)?;

        assert_eq!(firewall_string, expected_firewall_string);
        assert_ne!(firewall_string, firewall_before_string);

        delete_config("firewall.namibrule_8749447068245335151")?;

        let mut firewall = File::open("config/firewall")?;

        firewall_string = "".to_string();
        firewall.read_to_string(&mut firewall_string)?;

        assert_ne!(firewall_string, expected_firewall_string);
        assert_eq!(firewall_string, firewall_before_string);

        Ok(())
    }

    #[test]
    fn test_apply_list_() -> Result<()> {
        init();

        let mut uci = UCI::new()?;
        uci.set_config_dir("config")?;

        let mut vec = Vec::new();
        for i in 0..10 {
            vec.push(ConfigFirewall::new(
                RuleName::new(format!("Regel{}", i)),
                EnRoute::Src(EnNetwork::Lan),
                EnRoute::Des(EnNetwork::Wan),
                Protocol::tcp(),
                EnTarget::DROP,
                EnOptionalSettings::None,
            ));
        }
        apply_config_list(vec)?;
        Ok(())
    }

    #[test]
    fn test_flash_() -> Result<()> {
        init();
        flash_config()?;
        Ok(())
    }

    fn init() {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).is_test(true).try_init();
    }
}
