use namib_shared::config_firewall::ConfigFirewall;

pub fn get_config_version() -> String {
    "1337".to_string()
}

pub fn apply_config(config_firewall: Vec<ConfigFirewall>) {
    debug!("TODO: applying config");
}
