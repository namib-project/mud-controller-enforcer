use namib_shared::config_firewall::FirewallConfig;
use nftnl::Table;

pub struct FirewallConfigState {
    pub current_firewall_config: Option<FirewallConfig>,
    pub current_nftnl_table: Option<Table>,
}

impl Default for FirewallConfigState {
    fn default() -> Self {
        FirewallConfigState {
            current_nftnl_table: None,
            current_firewall_config: None,
        }
    }
}
