use std::env;

pub mod firewall_service;

pub fn is_system_mode() -> bool {
    env::var("NAMIB_SYSTEM").as_deref() == Ok("1")
}
