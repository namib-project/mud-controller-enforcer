use namib_shared::config_firewall::FirewallConfig;
use tokio::sync::RwLock;

pub(crate) struct EnforcerState {
    pub firewall_cfg: RwLock<Option<FirewallConfig>>,
}

impl EnforcerState {
    pub fn new() -> EnforcerState {
        EnforcerState {
            firewall_cfg: RwLock::new(None),
        }
    }
}
