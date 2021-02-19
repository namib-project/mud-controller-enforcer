use namib_shared::firewall_config::EnforcerConfig;
use tokio::sync::RwLock;

pub(crate) struct EnforcerState {
    pub firewall_cfg: RwLock<Option<EnforcerConfig>>,
}

impl EnforcerState {
    pub fn new() -> EnforcerState {
        EnforcerState {
            firewall_cfg: RwLock::new(None),
        }
    }
}
