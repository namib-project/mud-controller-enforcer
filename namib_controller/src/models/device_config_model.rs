// Copyright 2022, Jan Hensel
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::net::IpAddr;

use namib_shared::firewall_config::RuleTargetHost;

#[derive(Debug, Clone, Serialize)]
pub struct ConfiguredServerDbo {
    pub server: String,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AdministrativeContext {
    pub dns_mappings: Vec<DefinedServer>,
    pub ntp_mappings: Vec<DefinedServer>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DefinedServer {
    Ip(IpAddr),
    Url(String),
}

impl From<&DefinedServer> for RuleTargetHost {
    fn from(s: &DefinedServer) -> Self {
        match s {
            DefinedServer::Ip(addr) => RuleTargetHost::IpAddr(*addr),
            DefinedServer::Url(mud_url) => RuleTargetHost::Hostname(mud_url.clone()),
        }
    }
}
