use std::env;

pub mod dns;
pub mod firewall_service;
pub mod state;

pub fn is_system_mode() -> bool {
    env::var("NAMIB_SYSTEM").as_deref() == Ok("1")
}
