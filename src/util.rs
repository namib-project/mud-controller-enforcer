// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{fs::File, io, result::Result};

/// Utility function to open a file with a `BufReader` and then pass the `BufReader` into a method
///
/// # Errors
/// if opening the file fails or if `F` returns an error
#[allow(clippy::map_err_ignore)]
pub fn open_file_with<F, T>(file: &str, method: F) -> io::Result<T>
where
    F: FnOnce(&mut dyn io::BufRead) -> Result<T, ()>,
{
    let certfile = File::open(file)?;
    let mut reader = io::BufReader::new(certfile);
    let val = method(&mut reader).map_err(|_| io::Error::from(io::ErrorKind::Other))?;
    Ok(val)
}
