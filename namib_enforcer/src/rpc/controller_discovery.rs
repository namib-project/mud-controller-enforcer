// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::time::Duration;

use async_dnssd::{ResolvedHostFlags, ScopedSocketAddr, StreamTimeoutExt};
use futures::{future, Stream, TryStreamExt};

use crate::error::Result;

const SEARCH_TIMEOUT: Duration = Duration::from_secs(10);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);
const ADDRESS_TIMEOUT: Duration = Duration::from_secs(3);

pub fn discover_controllers(reg_type: &str) -> impl Stream<Item = Result<ScopedSocketAddr>> {
    async_dnssd::browse(reg_type)
        .timeout(SEARCH_TIMEOUT)
        .try_filter_map(|service| {
            future::ok({
                let added = service.flags.contains(async_dnssd::BrowsedFlags::ADD);

                info!(
                    "Service {}{:?}@{:?} (type {:?})\t\t[{:?}]",
                    if added { '+' } else { '-' },
                    service.service_name,
                    service.domain,
                    service.reg_type,
                    service
                );

                if added {
                    Some(service.resolve().timeout(RESOLVE_TIMEOUT))
                } else {
                    // only resolve added services
                    None
                }
            })
        })
        .try_flatten()
        .map_ok(|r| {
            info!(
                "Resolved on {:?}: {:?}:{}\t\t[{:?}]",
                r.interface, r.host_target, r.port, r
            );

            r.resolve_socket_address().timeout(ADDRESS_TIMEOUT)
        })
        .try_flatten()
        .try_filter_map(|result| {
            future::ok({
                if result.flags.intersects(ResolvedHostFlags::ADD) {
                    info!("Address {} \t\t [{:?}]", result.address, result);

                    Some(result.address)
                } else {
                    None
                }
            })
        })
        .map_err(std::convert::Into::into)
}
