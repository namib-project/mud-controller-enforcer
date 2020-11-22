use crate::{error::*, uci::*};
use namib_shared::config_firewall::*;
use std::process::{Command, Output};
//TODO Test für löschen unserer Rules. Attribute Option Namib prüfen, Liste von Regeln anwenden (mit format! (einzigartiger name)) (flash) und commit.

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

fn apply_config(cfg: ConfigFirewall) -> Result<()> {
    let mut uci = UCI::new()?;
    uci.set_config_dir("config")?;
    uci.set("firewall.namibrule", "rule")?;
    let cfg_option = cfg.to_option();
    for c in cfg_option.iter() {
        uci.set(format!("firewall.namibrule.{}", c.0).as_str(), c.1.as_str())?;
    }
    uci.set("firewall.namibrule.namib", "1");
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
    use crate::error::*;
    #[test]
    fn testsmt() -> Result<()> {
        init();
        apply_config(ConfigFirewall::new(
            RuleName::new("Regel1".to_string()),
            EnRoute::Src(EnNetwork::VPN),
            EnRoute::Des(EnNetwork::Lan),
            Protocol::tcp(),
            EnTarget::REJECT,
            EnOptionalSettings::None,
        ))?;
        Ok(())
    }

    fn init() {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).is_test(true).try_init();
    }
}
