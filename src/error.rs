use snafu::{Backtrace, Snafu};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("IoError: {}", source), context(false))]
    IoError {
        source: std::io::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("TlsError: {}", source), context(false))]
    TlsError {
        source: rustls::TLSError,
        backtrace: Backtrace,
    },
    #[snafu(display("JoinError: {}", source), context(false))]
    JoinError {
        source: tokio::task::JoinError,
        backtrace: Backtrace,
    },
    #[snafu(display("InvalidDNSNameError: {}", source), context(false))]
    InvalidDNSNameError {
        source: tokio_rustls::webpki::InvalidDNSNameError,
        backtrace: Backtrace,
    },
    #[snafu(display("ConnectionError"), visibility(pub))]
    ConnectionError {
        message: &'static str,
        backtrace: Backtrace,
    },
    #[snafu(display("DotEnvError: {}", source), context(false))]
    DotEnvError {
        source: dotenv::Error,
        backtrace: Backtrace,
    },
}

pub type Result<T> = std::result::Result<T, Error>;
