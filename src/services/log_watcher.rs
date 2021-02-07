use std::{
    fs,
    fs::File,
    io,
    io::BufRead,
    path::Path,
    sync::{mpsc::channel, Arc},
    thread::sleep,
    time::Duration,
};

use notify::{DebouncedEvent, RecursiveMode, Watcher};
use tokio::{runtime::Runtime, sync::Mutex, time};

use namib_shared::rpc::RPCClient;

use crate::{error::Result, rpc::rpc_client, services};
use namib_shared::firewall_config::FirewallConfig;

use tokio::sync::RwLock;

pub fn watch(client: &Arc<Mutex<RPCClient>>, config: &Arc<RwLock<Option<FirewallConfig>>>) {
    debug!("Starting dnsmasq.log watcher");
    let (tx, rx) = channel();
    let mut watcher = notify::watcher(tx, Duration::from_secs(10)).unwrap();

    let path: &Path;
    let tmp_path: &Path;
    if services::is_system_mode() {
        path = "/tmp/dnsmasq.log".as_ref();
        tmp_path = "/tmp/dnsmasq.log.tmp".as_ref();
    } else {
        path = "dnsmasq.log".as_ref();
        tmp_path = "dnsmasq.log.tmp".as_ref();
    };
    if !path.is_file() {
        warn!("Skipping watching dnsmasq.log, since dnsmasq is either not running or wrongly configured");
        return;
    }
    if let Err(e) = read_log_file(&client, &config, path, tmp_path) {
        warn!("failed to process file {}", e);
    }
    loop {
        if let Err(e) = watcher.watch(path, RecursiveMode::NonRecursive) {
            error!("Failed to watch dnsmasq.log! {}", e);
            sleep(Duration::from_secs(5));
            continue;
        }

        loop {
            match rx.recv() {
                Ok(DebouncedEvent::Write(_)) | Ok(DebouncedEvent::NoticeWrite(_)) => {
                    // inner function to make use of Result
                    if let Err(e) = read_log_file(&client, &config, path, tmp_path) {
                        warn!("failed to process file {}", e);
                    }
                },
                Err(e) => error!("watch error: {}", e),
                _ => {},
            }
        }
    }
}

fn read_log_file(
    client: &Arc<Mutex<RPCClient>>,
    config: &Arc<RwLock<Option<FirewallConfig>>>,
    path: &Path,
    tmp_path: &Path,
) -> Result<()> {
    debug!("reading dnsmasq log file");
    fs::rename(path, tmp_path)?;
    let lines = io::BufReader::new(File::open(tmp_path)?).lines();
    // create async runtime to run rpc client
    Runtime::new()?.block_on(async {
        let mut reader;
        let known_devices = loop {
            reader = config.read().await;
            match &*reader {
                Some(config) => break config.known_devices(),
                None => {
                    drop(reader);
                    time::sleep(Duration::from_secs(1)).await
                },
            }
            debug!("waiting for known devices");
        };
        debug!("acquired known devices");
        let lines = lines
            .filter(|l| {
                if let Ok(l) = l {
                    known_devices
                        .iter()
                        .filter(|d| d.collect_data)
                        .any(|d| l.contains(&d.ip.to_string()))
                } else {
                    false
                }
            })
            .collect::<io::Result<_>>()?;
        let mut client = client.lock().await;
        client.send_logs(rpc_client::current_rpc_context(), lines).await
    })?;
    Ok(())
}
