use std::{
    cmp::{max, Ordering},
    collections::{BinaryHeap, HashMap, HashSet},
    hash::{Hash, Hasher},
    net::IpAddr,
    ops::{Add, Deref},
    pin::Pin,
    sync::Arc,
    time::Instant,
};

use tokio::sync::{Mutex, Notify, RwLock, RwLockWriteGuard};
use trust_dns_resolver::{
    config::LookupIpStrategy, error::ResolveError, lookup_ip::LookupIp, AsyncResolver, TokioAsyncResolver,
};

/// The minimum time that is waited before refreshing the dns cache even though there are entries with a TTL of 0.
const MIN_TIME_BEFORE_REFRESH: std::time::Duration = std::time::Duration::from_secs(30);

/// Represents an entry in the DNS refresh queue. Entries define a custom ordering based on the TTLs of their corresponding DNS cache entries.
#[derive(Debug, Clone)]
struct DnsRefreshQueueEntry {
    /// A copy of the DNS cache entry that should be refreshed (with shared references to the lookup result and watchers).
    cache_entry: DnsCacheEntry,
}

impl Eq for DnsRefreshQueueEntry {}

impl PartialEq for DnsRefreshQueueEntry {
    fn eq(&self, other: &Self) -> bool {
        self.cache_entry.lookup_result.valid_until() == other.cache_entry.lookup_result.valid_until()
    }
}

impl Ord for DnsRefreshQueueEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .cache_entry
            .lookup_result
            .valid_until()
            .cmp(&self.cache_entry.lookup_result.valid_until())
    }
}

impl PartialOrd for DnsRefreshQueueEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Represents an entry in the DNS cache.
#[derive(Debug, Clone)]
struct DnsCacheEntry {
    /// The (host-)name for which this entry is a cached result.
    name: String,
    /// A reference to the cached lookup result.
    lookup_result: Arc<LookupIp>,
    /// A shared mutable reference to a set of watcher senders for the watchers that want to be notified of changes to this entry.
    watchers: Arc<RwLock<HashSet<Arc<Pin<Box<DnsWatcherSender>>>>>>,
}

/// DNS resolution cache for the DNS service.
#[derive(Debug, Clone)]
struct DnsServiceCache {
    /// Resolver instance used to resolve DNS entries.
    resolver: TokioAsyncResolver,
    /// Refresh queue to refresh expiring DNS entries (using the DnsServices auto_refresher_task()).
    refresh_queue: BinaryHeap<DnsRefreshQueueEntry>,
    /// Cache entries for the DNS cache.
    cache_data: HashMap<String, DnsCacheEntry>,
}

impl DnsServiceCache {
    fn new() -> Result<DnsServiceCache, ResolveError> {
        let (resolver_conf, mut resolver_opts) = trust_dns_resolver::system_conf::read_system_conf()?;
        resolver_opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        Ok(DnsServiceCache {
            resolver: AsyncResolver::tokio(resolver_conf, resolver_opts)?,
            refresh_queue: BinaryHeap::default(),
            cache_data: HashMap::default(),
        })
    }

    /// Returns a DNS resolution result if it is cached, None otherwise.
    fn resolve_if_cached(&self, name: &str) -> Option<DnsCacheEntry> {
        self.cache_data.get(name).map(|v| v.deref().clone())
    }

    /// Resolves a supplied name and adds it to the DNS cache.
    async fn lookup_and_cache(&mut self, name: &str) -> Result<DnsCacheEntry, ResolveError> {
        let lookup_result = DnsCacheEntry {
            name: String::from(name),
            lookup_result: Arc::new(self.resolver.lookup_ip(name).await?),
            watchers: Arc::new(RwLock::new(HashSet::new())),
        };
        self.cache_data.insert(name.into(), lookup_result);
        self.refresh_queue.push(DnsRefreshQueueEntry {
            cache_entry: self.cache_data.get(name).unwrap().clone(),
        });
        Ok(self.cache_data.get(name).unwrap().clone())
    }

    /// Resolves the supplied DNS name. If the name is already in the DNS cache, returns the cached result instead.
    async fn resolve(&mut self, name: &str) -> Result<DnsCacheEntry, ResolveError> {
        match self.cache_data.get(name) {
            Some(v) => Ok(v.clone()),
            None => self.lookup_and_cache(name).await,
        }
    }
}

/// Helper struct used to notify DNS watchers of changes to watched cache entries.
#[derive(Debug)]
struct DnsWatcherSender {
    updated_names: Arc<Mutex<HashSet<String>>>,
    notify: Arc<Notify>,
}

impl Eq for DnsWatcherSender {}

impl PartialEq for DnsWatcherSender {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

impl Hash for DnsWatcherSender {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self as *const DnsWatcherSender).hash(state);
    }
}

/// DNS Service which provides methods to query a DNS cache for entries and
pub(crate) struct DnsService {
    cache: Arc<RwLock<DnsServiceCache>>,
}

impl DnsService {
    pub fn new() -> Result<DnsService, ResolveError> {
        Ok(DnsService {
            cache: Arc::new(RwLock::new(DnsServiceCache::new()?)),
        })
    }

    /// Asynchronous task to automatically refresh dns cache entries as they expire.
    pub async fn auto_refresher_task(&mut self) {
        let mut next_expiry_time = None;
        loop {
            tokio::time::sleep_until(max(
                next_expiry_time.unwrap_or_else(Instant::now).into(),
                Instant::now().add(MIN_TIME_BEFORE_REFRESH).into(),
            ))
            .await;
            debug!("Starting new update cycle of DNS cache.");
            let mut cache = self.cache.write().await;
            let refresh_start = Instant::now();
            let mut watchers_to_notify = HashSet::new();
            let mut new_entries = Vec::new();
            while let Some(queue_element) = cache.refresh_queue.pop() {
                // remove cache entries without watchers
                if queue_element.cache_entry.watchers.read().await.is_empty() {
                    cache.cache_data.remove(&queue_element.cache_entry.name);
                    continue;
                }
                if let Some(duration_until_invalid) = queue_element
                    .cache_entry
                    .lookup_result
                    .valid_until()
                    .checked_duration_since(refresh_start)
                {
                    if duration_until_invalid > MIN_TIME_BEFORE_REFRESH {
                        // Return last queue element to queue.
                        cache.refresh_queue.push(queue_element);
                        break;
                    }
                }
                new_entries
                    .push(DnsService::refresh_dns_entry(queue_element, &mut cache, &mut watchers_to_notify).await);
            }
            cache.refresh_queue.append(&mut new_entries.into());
            watchers_to_notify.iter().for_each(|w| w.notify.notify_one());
            next_expiry_time = cache
                .refresh_queue
                .peek()
                .map(|v| v.cache_entry.lookup_result.valid_until());
            debug!("Finished DNS cache refresh cycle.");
        }
    }

    async fn refresh_dns_entry(
        queue_element: DnsRefreshQueueEntry,
        cache: &mut RwLockWriteGuard<'_, DnsServiceCache>,
        watchers_to_notify: &mut HashSet<Arc<Pin<Box<DnsWatcherSender>>>>,
    ) -> DnsRefreshQueueEntry {
        debug!(
            "Refreshing DNS cache entry for {:?} because cache entry expired.",
            queue_element.cache_entry.name
        );
        let name = queue_element.cache_entry.name.as_str();
        let new_entry = cache.resolver.lookup_ip(name).await.map(|v| DnsCacheEntry {
            name: name.to_string(),
            lookup_result: Arc::new(v),
            watchers: queue_element.cache_entry.watchers.clone(),
        });
        if let Ok(new_entry) = new_entry {
            let new_set: HashSet<IpAddr> = new_entry.lookup_result.iter().collect();
            let old_set: HashSet<IpAddr> = queue_element.cache_entry.lookup_result.iter().collect();
            if new_set != old_set {
                debug!(
                    "IP address set for {:?} has changed from {:?} to {:?}, notifying watchers of DNS entry change.",
                    name, old_set, new_set
                );
                let watchers = new_entry.watchers.read().await;
                for w in watchers.iter() {
                    watchers_to_notify.insert(w.clone());
                    w.updated_names.lock().await.insert(name.to_string());
                }
            }
            cache.cache_data.insert(name.to_string(), new_entry);
            DnsRefreshQueueEntry {
                cache_entry: cache.cache_data.get(name).unwrap().clone(),
            }
        } else {
            queue_element
        }
    }

    /// Create a `DnsWatcher` instance which can be used to keep track of dns entry changes.
    pub fn create_watcher(&self) -> DnsWatcher {
        DnsWatcher {
            cache: self.cache.clone(),
            sender: Arc::new(Pin::new(Box::new(DnsWatcherSender {
                updated_names: Arc::default(),
                notify: Arc::default(),
            }))),
            current_watched_entries: Mutex::default(),
        }
    }
}

/// Struct which can be used to keep track of dns entry changes.
pub(crate) struct DnsWatcher {
    /// Reference to the DNS cache of the DnsService.
    cache: Arc<RwLock<DnsServiceCache>>,
    /// Reference to a sender instance which is added to cache entries if the watches wishes to be notified of changes.
    sender: Arc<Pin<Box<DnsWatcherSender>>>,
    /// Set of currently watched DNS entries.
    current_watched_entries: Mutex<HashSet<String>>,
}

impl DnsWatcher {
    /// Resolves the given DNS name and adds the name to the list of watched DNS entries.
    pub async fn resolve_and_watch(&self, name: &str) -> Result<LookupIp, ResolveError> {
        let mut cache = self.cache.write().await;
        let resolved_value = cache.resolve(name).await?;
        resolved_value.watchers.write().await.insert(self.sender.clone());
        self.current_watched_entries.lock().await.insert(name.into());
        Ok(resolved_value.lookup_result.deref().clone())
    }

    /// Removes a name from the list of watched DNS entries.
    pub async fn remove_watched_name(&self, name: &str) {
        let cache = self.cache.read().await;
        let cache_entry = cache.resolve_if_cached(name).unwrap();
        cache_entry.watchers.write().await.remove(&self.sender.clone());
        self.current_watched_entries.lock().await.remove(name);
    }

    /// Clears the list of watched DNS entries.
    pub async fn clear_watched_names(&self) {
        let current_watched_entries = self.current_watched_entries.lock().await.clone();
        for name in current_watched_entries {
            self.remove_watched_name(name.as_str()).await;
        }
    }

    /// Yield until a change to any of the watched DNS entries of this watcher occurs.
    /// Returns immediately in case a change has already happened but was not waited for.
    pub async fn address_changed(&self) {
        self.sender.notify.notified().await
    }
}

#[cfg(test)]
mod test {
    use crate::{error::Result, services::dns::DnsService};

    #[tokio::test]
    async fn test() -> Result<()> {
        let service = DnsService::new().unwrap();
        let watcher = service.create_watcher();
        let lookup = watcher.resolve_and_watch("www.google.com").await?;
        let cache_entry = watcher.cache.read().await.resolve_if_cached("www.google.com").unwrap();
        assert_eq!(cache_entry.name, "www.google.com");
        assert!(cache_entry.watchers.read().await.contains(watcher.sender.as_ref()));
        assert_eq!(cache_entry.lookup_result.as_lookup(), lookup.as_lookup());
        assert!(watcher.cache.read().await.refresh_queue.peek().is_some());

        watcher.resolve_and_watch("www.youtube.com").await?;
        watcher.resolve_and_watch("www.google.com").await?;

        assert!(watcher
            .current_watched_entries
            .lock()
            .await
            .eq(&["www.google.com", "www.youtube.com"]
                .iter()
                .map(ToString::to_string)
                .collect()));

        assert_eq!(
            watcher
                .cache
                .read()
                .await
                .resolve_if_cached("www.google.com")
                .unwrap()
                .watchers
                .read()
                .await
                .len(),
            1
        );
        assert!(watcher.cache.read().await.resolve_if_cached("www.blabla.com").is_none());

        watcher.remove_watched_name("www.google.com").await;

        let cache_entry = watcher.cache.read().await.resolve_if_cached("www.google.com").unwrap();
        assert!(cache_entry.watchers.read().await.is_empty());
        assert!(watcher
            .current_watched_entries
            .lock()
            .await
            .eq(&["www.youtube.com"].iter().map(ToString::to_string).collect()));

        Ok(())
    }
}
