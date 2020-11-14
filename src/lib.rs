use std::fs::File;
use std::io;

use tokio_serde::formats::Bincode;

pub mod models;
pub mod rpc;

pub fn open_file_with<F, T>(file: &str, method: F) -> io::Result<T>
where
    F: FnOnce(&mut dyn io::BufRead) -> Result<T, ()>,
{
    let certfile = File::open(file)?;
    let mut reader = io::BufReader::new(certfile);
    Ok(method(&mut reader).map_err(|_| io::Error::from(io::ErrorKind::Other))?)
}

pub fn codec<Item, SinkItem>() -> fn() -> Bincode<Item, SinkItem> {
    Bincode::default
}
