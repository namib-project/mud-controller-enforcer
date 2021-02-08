#![feature(async_closure)]
use futures::{future::err, TryFutureExt};
use std::{
    cmp::{max, Ordering},
    collections::{hash_map::DefaultHasher, BinaryHeap, HashMap, HashSet},
    hash::{Hash, Hasher},
    net::IpAddr,
    ops::{Add, Deref, Sub},
    sync::Arc,
    time::Instant,
};
use tokio::sync::{Mutex, Notify, RwLock};
use trust_dns_resolver::{error::ResolveError, lookup_ip::LookupIp, AsyncResolver, TokioAsyncResolver};

const MIN_TIME_BEFORE_REFRESH: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Debug, Clone)]
struct DnsRefreshQueueEntry {
    cache_entry: DnsCacheEntry,
}

impl Eq for DnsRefreshQueueEntry {}

impl PartialEq for DnsRefreshQueueEntry {
    fn eq(&self, other: &Self) -> bool {
        self.cache_entry
            .lookup_result
            .valid_until()
            .eq(&other.cache_entry.lookup_result.valid_until())
    }
}

impl Ord for DnsRefreshQueueEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cache_entry
            .lookup_result
            .valid_until()
            .cmp(&other.cache_entry.lookup_result.valid_until())
            .reverse()
    }
}

impl PartialOrd for DnsRefreshQueueEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone)]
struct DnsCacheEntry {
    name: String,
    lookup_result: Arc<LookupIp>,
    watchers: Arc<RwLock<HashSet<Arc<DnsWatcherSender>>>>,
}

#[derive(Debug, Clone)]
struct DnsServiceCache {
    resolver: TokioAsyncResolver,
    refresh_queue: BinaryHeap<DnsRefreshQueueEntry>,
    cache_data: HashMap<String, DnsCacheEntry>,
}

impl DnsServiceCache {
    fn new() -> Result<DnsServiceCache, ResolveError> {
        Ok(DnsServiceCache {
            resolver: AsyncResolver::tokio_from_system_conf()?,
            refresh_queue: Default::default(),
            cache_data: Default::default(),
        })
    }

    fn resolve_if_cached(&self, name: &str) -> Option<DnsCacheEntry> {
        self.cache_data.get(name).map(|v| v.deref().clone())
    }

    async fn lookup_and_cache(&mut self, name: &str) -> Result<DnsCacheEntry, ResolveError> {
        let mut lookup_result = DnsCacheEntry {
            name: String::from(name),
            lookup_result: Arc::new(self.resolver.lookup_ip(name).await?),
            watchers: Arc::new(RwLock::new(HashSet::new())),
        };
        self.cache_data.insert(name.into(), lookup_result);
        self.refresh_queue.push(DnsRefreshQueueEntry {
            cache_entry: self.cache_data.get(name.into()).unwrap().clone(),
        });
        Ok(self.cache_data.get(name.into()).unwrap().clone())
    }

    async fn resolve(&mut self, name: &str) -> Result<DnsCacheEntry, ResolveError> {
        match self.cache_data.get(name) {
            Some(v) => Ok(v.clone()),
            None => self.lookup_and_cache(name).await,
        }
    }
}

#[derive(Clone, Debug)]
struct DnsWatcherSender {
    updated_names: Arc<Mutex<HashSet<String>>>,
    notify: Arc<Notify>,
}

impl Eq for DnsWatcherSender {}

impl PartialEq for DnsWatcherSender {
    fn eq(&self, other: &Self) -> bool {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        let v1 = hasher.finish();
        let mut hasher = DefaultHasher::new();
        other.hash(&mut hasher);
        v1.eq(&hasher.finish())
    }
}

impl Hash for DnsWatcherSender {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self as *const DnsWatcherSender).hash(state);
    }
}

pub(crate) struct DnsService {
    cache: Arc<RwLock<DnsServiceCache>>,
}

impl DnsService {
    pub fn new() -> Result<DnsService, ResolveError> {
        Ok(DnsService {
            cache: Arc::new(RwLock::new(DnsServiceCache::new()?)),
        })
    }

    pub async fn auto_refresher_task(&mut self) {
        let mut next_expiry_time = None;
        loop {
            tokio::time::sleep_until(max(
                next_expiry_time.unwrap_or(Instant::now()).into(),
                Instant::now().add(MIN_TIME_BEFORE_REFRESH).into(),
            ))
            .await;
            debug!("Starting new update cycle of DNS cache.");
            let mut cache = self.cache.write().await;
            let refresh_start = Instant::now();
            let mut watchers_to_notify = HashSet::new();
            let mut new_entries = Vec::new();
            while let Some(queue_element) = cache.refresh_queue.pop() {
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
                let name = queue_element.cache_entry.name.clone();
                debug!("Refreshing DNS cache entry for {:?} because cache entry expired.", name);
                let new_entry = cache.resolver.lookup_ip(name.as_str()).await.map(|v| DnsCacheEntry {
                    name: name.clone(),
                    lookup_result: Arc::new(v),
                    watchers: queue_element.cache_entry.watchers.clone(),
                });
                if let Ok(new_entry) = new_entry {
                    let new_set: HashSet<IpAddr> = new_entry.lookup_result.iter().collect();
                    let old_set: HashSet<IpAddr> = queue_element.cache_entry.lookup_result.iter().collect();
                    if !new_set.eq(&old_set) {
                        debug!(
                            "IP address set for {:?} has changed from {:?} to {:?}, notifying watchers of DNS entry change.",
                            name, old_set, new_set
                        );
                        let watchers = new_entry.watchers.read().await;
                        for w in watchers.iter() {
                            watchers_to_notify.insert(w.clone());
                            w.updated_names.lock().await.insert(name.clone());
                        }
                    }
                    cache.cache_data.remove(name.as_str());
                    cache.cache_data.insert(name.clone(), new_entry);
                    new_entries.push(DnsRefreshQueueEntry {
                        cache_entry: cache.cache_data.get(name.as_str()).unwrap().clone(),
                    });
                } else {
                    new_entries.push(queue_element);
                }
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

    pub fn create_watcher(&self) -> DnsWatcher {
        DnsWatcher {
            cache: self.cache.clone(),
            sender: Arc::new(DnsWatcherSender {
                updated_names: Default::default(),
                notify: Default::default(),
            }),
            current_watched_entries: Default::default(),
        }
    }
}

pub(crate) struct DnsWatcher {
    cache: Arc<RwLock<DnsServiceCache>>,
    sender: Arc<DnsWatcherSender>,
    current_watched_entries: Mutex<HashSet<String>>,
}

impl DnsWatcher {
    pub async fn resolve_and_watch(&self, name: &str) -> Result<LookupIp, ResolveError> {
        let mut cache = self.cache.write().await;
        let resolved_value = cache.resolve(name).await?;
        resolved_value.watchers.write().await.insert(self.sender.clone());
        self.current_watched_entries.lock().await.insert(name.into());
        Ok(resolved_value.lookup_result.deref().clone())
    }

    pub async fn remove_watched_name(&self, name: &str) {
        let mut cache = self.cache.read().await;
        let cache_entry = cache.resolve_if_cached(name).unwrap();
        cache_entry.watchers.write().await.remove(&self.sender.clone());
        self.current_watched_entries.lock().await.remove(name.into());
    }

    pub async fn clear_watched_names(&self) {
        for name in self.current_watched_entries.lock().await.clone() {
            self.remove_watched_name(name.as_str()).await;
        }
    }

    pub async fn address_changed(&self) -> () {
        self.sender.notify.notified().await
    }
}
