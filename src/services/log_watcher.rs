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

use crate::{error::Result, rpc::rpc_client, services, Enforcer};

use tokio::{runtime::Builder, sync::RwLock};

pub fn watch(enforcer: &Arc<RwLock<Enforcer>>) {
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
    loop {
        if let Err(e) = watcher.watch(path, RecursiveMode::NonRecursive) {
            debug!("Failed to watch dnsmasq.log! {:?}", e);
            sleep(Duration::from_secs(10));
            continue;
        }
        if let Err(e) = read_log_file(&enforcer, path, tmp_path) {
            warn!("failed to process file {:?}", e);
        }

        loop {
            match rx.recv() {
                Ok(DebouncedEvent::Write(_)) | Ok(DebouncedEvent::NoticeWrite(_)) => {
                    // inner function to make use of Result
                    if let Err(e) = read_log_file(&enforcer, path, tmp_path) {
                        debug!("failed to process file {:?}", e);
                    }
                },
                Ok(_) => {},
                Err(e) => warn!("watch error: {:?}", e),
            }
        }
    }
}

fn read_log_file(enforcer: &Arc<RwLock<Enforcer>>, path: &Path, tmp_path: &Path) -> Result<()> {
    debug!("reading dnsmasq log file");
    // it is possible to lose a logline here, but we cannot lock the file either
    fs::copy(path, tmp_path)?;
    fs::File::create(path)?;
    let lines = io::BufReader::new(File::open(tmp_path)?).lines();
    // create async runtime to run rpc client
    Builder::new_current_thread().enable_all().build()?.block_on(async {
        let enforcer = enforcer.read().await;
        let ips_to_filter = enforcer
            .config
            .devices()
            .iter()
            .filter(|d| d.collect_data)
            .flat_map(|d| {
                Iterator::chain(
                    d.ipv4_addr.iter().map(ToString::to_string),
                    d.ipv6_addr.iter().map(ToString::to_string),
                )
            })
            .collect::<Vec<_>>();
        debug!("acquired known devices");
        let lines = lines
            .filter(|l| {
                if let Ok(l) = l {
                    ips_to_filter.iter().any(|ip| l.contains(ip))
                } else {
                    false
                }
            })
            .collect::<io::Result<Vec<_>>>()?;
        if lines.is_empty() {
            return Ok(());
        }
        enforcer
            .client
            .as_ref()
            .expect("RPC client of enforcer must be initialised before starting log watcher.")
            .send_logs(rpc_client::current_rpc_context(), lines)
            .await
    })?;
    Ok(())
}
