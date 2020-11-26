#![allow(clippy::pub_enum_variant_names)]

use snafu::{Backtrace, Snafu};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("IoError: {}", source), context(false))]
    IoError { source: std::io::Error, backtrace: Backtrace },
    #[snafu(display("TlsError: {}", source), context(false))]
    TlsError { source: rustls::TLSError, backtrace: Backtrace },
    #[snafu(display("JoinError: {}", source), context(false))]
    JoinError { source: tokio::task::JoinError, backtrace: Backtrace },
    #[snafu(display("InvalidDNSNameError: {}", source), context(false))]
    InvalidDNSNameError {
        source: tokio_rustls::webpki::InvalidDNSNameError,
        backtrace: Backtrace,
    },
    #[snafu(display("ConnectionError {}", message), visibility(pub))]
    ConnectionError { message: &'static str, backtrace: Backtrace },
    #[snafu(display("DotEnvError: {}", source), context(false))]
    DotEnvError { source: dotenv::Error, backtrace: Backtrace },
    #[snafu(display("UCIError: {}", message), visibility(pub))]
    UCIError { message: String, backtrace: Backtrace },
    #[snafu(display("IntoStringError: {}", source), context(false))]
    IntoStringError { source: std::ffi::IntoStringError, backtrace: Backtrace },
    #[snafu(display("Utf8Error: {}", source), context(false))]
    Utf8Error { source: std::str::Utf8Error, backtrace: Backtrace },
    #[snafu(display("NulError: {}", source), context(false))]
    NulError { source: std::ffi::NulError, backtrace: Backtrace },
}

pub type Result<T> = std::result::Result<T, Error>;
