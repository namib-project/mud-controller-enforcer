// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use snafu::{Backtrace, Snafu};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("IoError: {}", source), context(false))]
    Io {
        source: std::io::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("NativeTlsError: {}", source), context(false))]
    NativeTls {
        source: tokio_native_tls::native_tls::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("JoinError: {}", source), context(false))]
    Join {
        source: tokio::task::JoinError,
        backtrace: Backtrace,
    },
    #[snafu(display("ConnectionError {}", message), visibility(pub))]
    Connection {
        message: &'static str,
        backtrace: Backtrace,
    },
    #[snafu(display("DotEnvError: {}", source), context(false))]
    DotEnv {
        source: dotenv::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("TrustDnsResolverError: {}", source), context(false))]
    TrustDnsResolver {
        source: Box<trust_dns_resolver::error::ResolveError>,
        backtrace: Backtrace,
    },
    #[cfg(feature = "uci")]
    #[snafu(display("UciError: {}", source), context(false))]
    Uci {
        source: rust_uci::error::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("IntoStringError: {}", source), context(false))]
    IntoString {
        source: std::ffi::IntoStringError,
        backtrace: Backtrace,
    },
    #[snafu(display("Utf8Error: {}", source), context(false))]
    Utf8 {
        source: std::str::Utf8Error,
        backtrace: Backtrace,
    },
    #[snafu(display("NulError: {}", source), context(false))]
    Nul {
        source: std::ffi::NulError,
        backtrace: Backtrace,
    },
    #[snafu(display("NoneError"), visibility(pub))]
    None { backtrace: Backtrace },
    #[snafu(display("SerdeError {}", source), context(false))]
    Serde {
        source: serde_json::Error,
        backtrace: Backtrace,
    },
}

impl From<trust_dns_resolver::error::ResolveError> for Error {
    fn from(resolve_error: trust_dns_resolver::error::ResolveError) -> Self {
        Box::new(resolve_error).into()
    }
}

pub type Result<T> = std::result::Result<T, Error>;
