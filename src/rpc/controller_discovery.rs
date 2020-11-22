use std::time::Duration;

use futures::{future, Stream, TryStreamExt};
use log::*;

use async_dnssd::{ResolvedHostFlags, ScopedSocketAddr, StreamTimeoutExt};

use crate::error::*;

const SEARCH_TIMEOUT: Duration = Duration::from_secs(10);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);
const ADDRESS_TIMEOUT: Duration = Duration::from_secs(3);

pub fn discover_controllers(reg_type: &str) -> Result<impl Stream<Item=Result<ScopedSocketAddr>>> {
    let result = async_dnssd::browse(reg_type)?
        .timeout(SEARCH_TIMEOUT)?
        .try_filter_map(|service| async move {
            let added = service.flags.contains(async_dnssd::BrowsedFlags::ADD);

            info!(
                "Service {}{:?}@{:?} (type {:?})\t\t[{:?}]",
                if added { '+' } else { '-' },
                service.service_name,
                service.domain,
                service.reg_type,
                service
            );

            if !added {
                // only resolve added services
                return Ok(None);
            }

            Ok(Some(service.resolve()?.timeout(RESOLVE_TIMEOUT)?))
        })
        .try_flatten()
        .try_filter_map(|r| async move {
            info!("Resolved on {:?}: {:?}:{}\t\t[{:?}]", r.interface, r.host_target, r.port, r);

            Ok(Some(r.resolve_socket_address()?.timeout(ADDRESS_TIMEOUT)?))
        })
        .try_flatten()
        .try_filter_map(|result| {
            future::ready({
                if result.flags.intersects(ResolvedHostFlags::ADD) {
                    info!("Address {} \t\t [{:?}]", result.address, result);

                    Ok(Some(result.address))
                } else {
                    Ok(None)
                }
            })
        })
        .map_err(|e| e.into());

    Ok(result)
}
