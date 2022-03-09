// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

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
use tokio::{runtime::Builder, sync::RwLock};

use crate::{rpc::rpc_client, services, Enforcer};

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

fn read_log_file(enforcer: &Arc<RwLock<Enforcer>>, path: &Path, tmp_path: &Path) -> io::Result<()> {
    debug!("reading dnsmasq log file");
    // it is possible to lose a logline here, but we cannot lock the file either
    fs::copy(path, tmp_path)?;
    fs::File::create(path)?;
    let lines = io::BufReader::new(File::open(tmp_path)?).lines();
    // create async runtime to run rpc client
    Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(handle_log_lines(&enforcer, lines))?;
    Ok(())
}

async fn handle_log_lines(
    enforcer: &RwLock<Enforcer>,
    lines: impl Iterator<Item = io::Result<String>>,
) -> io::Result<()> {
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
        .send_logs(rpc_client::current_rpc_context(), lines)
        .await
}

#[cfg(not(unix))]
pub async fn watch_np0f(enforcer: Arc<RwLock<Enforcer>>) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
pub async fn watch_np0f(enforcer: Arc<RwLock<Enforcer>>) {
    debug!("Starting neop0f.cmd watcher");
    match tokio::fs::remove_file("/tmp/neop0f.sock").await {
        Ok(_) => Ok(()),
        Err(e) => match e.kind() {
            std::io::ErrorKind::NotFound => Ok(()),
            e => Err(e),
        },
    }
    .expect("Unable to get access to socket file");
    let listener =
        tokio::net::UnixListener::bind("/tmp/neop0f.sock").expect("Could not open socket for neop0f log listener.");

    let mut active_listeners = Vec::new();
    while let Ok((event_stream, _)) = listener.accept().await {
        let enforcer = enforcer.clone();
        active_listeners.push(tokio::spawn(async move {
            if let Err(e) = handle_np0f_log_connection(enforcer, event_stream).await {
                warn!("Failed to receive np0f logs: {:?}", e)
            }
        }));
    }
    futures::future::join_all(active_listeners).await;
}

#[cfg(unix)]
async fn handle_np0f_log_connection(
    enforcer: Arc<RwLock<Enforcer>>,
    mut stream: tokio::net::UnixStream,
) -> io::Result<()> {
    use tokio::io::AsyncReadExt;
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    let lines = response.lines();
    handle_log_lines(&enforcer, lines.map(|l| Ok(l.to_string()))).await?;
    Ok(())
}
