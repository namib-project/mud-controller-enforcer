use std::{
    fmt,
    fs::File,
    io::Read,
    net::ToSocketAddrs,
    sync::{Arc, RwLock},
};

use acme_lib::{create_rsa_key, persist::FilePersist, Account, Directory, DirectoryUrl};
use get_if_addrs::get_if_addrs;
use lazy_static::lazy_static;
use regex::{Captures, Regex};
use reqwest::{Certificate, Identity};
use rustls_18::{
    sign::{any_supported_type, CertifiedKey},
    ClientHello, ResolvesServerCert, ServerConfig,
};
use sha3::{Digest, Sha3_224};
use snafu::ensure;

use crate::{
    app_config::APP_CONFIG,
    error::{self, Result},
    util::open_file_with,
};

/// `CertId` contains the url-safe base64-encoded sha3-hash of a certificate and may be regarded as a unique identifier for a Namib service.
#[derive(Clone)]
pub struct CertId(String);

impl CertId {
    /// Calculate the `CertId` for a given DER-encoded certificate.
    pub fn new(cert: &[u8]) -> Self {
        lazy_static! {
            static ref PATTERN: Regex = Regex::new("([A-Z])|([_-])").unwrap();
        }
        Self(
            PATTERN.replace_all(
                &base64::encode_config(Sha3_224::digest(cert), base64::URL_SAFE_NO_PAD),
                |c: &Captures| c.get(1).map(|c| c.as_str().to_lowercase()).unwrap_or_default(),
            )[..20]
                .to_string(),
        )
    }
}

impl fmt::Display for CertId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

fn get_letsencrypt_url() -> DirectoryUrl<'static> {
    if APP_CONFIG.staging {
        DirectoryUrl::LetsEncryptStaging
    } else {
        DirectoryUrl::LetsEncrypt
    }
}

lazy_static! {
    /// The letsencrypt API, use staging for local usage
    static ref ACME_API: Directory<FilePersist> =
        Directory::from_url(FilePersist::new("./acme"), get_letsencrypt_url()).unwrap();
    /// The account email does not have to be unique, calling this method will generate a private key for the account
    static ref ACCOUNT: Account<FilePersist> = ACME_API.account("namib@uni-bremen.de").unwrap();
    /// The server certificate for communicating with namib services
    static ref SERVER_CERT: Vec<rustls::Certificate> = open_file_with("certs/server.pem", rustls::internal::pemfile::certs)
            .expect("Could not find certs/server.pem");
    /// The certificate id (sha1 hash in base64)
    static ref SERVER_ID: CertId = CertId::new(SERVER_CERT[0].as_ref());
    /// The domain that this controllers certificate will be valid for
    pub static ref DOMAIN: String = format!("{}.{}", *SERVER_ID, APP_CONFIG.domain);
    /// store the CertifiedKey to not recreate it on every request
    static ref ACME_CERTIFIED_KEY: RwLock<Option<CertifiedKey>> = RwLock::new(None);
}

/// The server certificate resolver, which provides the tls certificate for the web frontend.
/// It relies on the `update_certs`-Job to request and persist a valid certificate.
pub struct CertResolver;

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<CertifiedKey> {
        // if a certificate is cached, simply return it
        if let Ok(g) = ACME_CERTIFIED_KEY.read() {
            if let Some(ref c) = *g {
                return Some(c.clone());
            }
        }
        // update the certificate cache
        if let Ok(mut g) = ACME_CERTIFIED_KEY.write() {
            // if another thread has already filled the cache, return it here
            if g.is_some() {
                return g.clone();
            }
            // check whether a certificate is persisted on disk and abort the connection if it is not
            let cert = match ACCOUNT.certificate(&*DOMAIN) {
                Ok(Some(c)) => CertifiedKey::new(
                    vec![rustls_18::Certificate(c.certificate_der())],
                    Arc::new(match any_supported_type(&rustls_18::PrivateKey(c.private_key_der())) {
                        Ok(key) => key,
                        Err(e) => {
                            error!("Could not load certificate from persisted certificate {:?}", e);
                            return None;
                        },
                    }),
                ),
                _ => return None,
            };
            *g = Some(cert.clone());
            info!("Loaded certificate for {} from disk", *DOMAIN);

            return Some(cert);
        }
        warn!("Cannot fulfil https request, since no certificate is present");
        None
    }
}

/// Checks whether the persisted certificate is present and valid for more than 15 days
/// and if not will request a new certificate from Let's Encrypt.
pub fn update_certs() -> Result<()> {
    debug!("checking if a certificate for {} exists", *DOMAIN);
    if let Some(c) = ACCOUNT.certificate(&DOMAIN).unwrap_or(None) {
        debug!("certificate found, days left: {}", c.valid_days_left());
        // if more than 15 days are left, nothing to do
        if c.valid_days_left() >= 15 {
            return Ok(());
        }
    }
    info!("ordering new certificate");
    let mut order = ACCOUNT.new_order(&DOMAIN, &[])?;
    let csr = loop {
        if let Some(csr) = order.confirm_validations() {
            info!("csr was validated");
            break csr;
        }

        let auths = order.authorizations()?;
        let challenge = auths[0].http_challenge();
        debug!("got http challenge: {}", challenge.http_token());
        let mut certs: Vec<u8> = Vec::new();
        // The server certificate for communicating with namib services
        File::open("certs/server.pem")?.read_to_end(&mut certs)?;
        // The private key for the server certificate
        File::open("certs/server-key.pem")?.read_to_end(&mut certs)?;
        let mut ca: Vec<u8> = Vec::new();
        // Use the global namib certificate here, since the httpchallenge service is always using the global one.
        File::open(&APP_CONFIG.global_namib_ca_cert)?.read_to_end(&mut ca)?;
        // send the httpchallenge token to the service.
        let response = reqwest::blocking::ClientBuilder::new()
            .tls_built_in_root_certs(false)
            .add_root_certificate(Certificate::from_pem(&ca)?)
            .identity(Identity::from_pem(&certs)?)
            .build()?
            .post(format!(
                "https://{}/.well-known/acme-challenge/{}",
                *DOMAIN,
                challenge.http_token()
            ))
            .body(challenge.http_proof())
            .send()?;
        ensure!(response.text()? == "ok", error::NoneError {});
        // tell LetsEncrypt to check the file
        challenge.validate(5000)?;
        // update the csr status
        order.refresh()?;
    };
    // create a private key for the new certificate
    let pkey = create_rsa_key(4096);
    // finalize the csr using the pkey and download the new certificate
    csr.finalize_pkey(pkey, 5000)?.download_and_save_cert()?;
    // make the resolver reload the certificate
    if let Ok(mut g) = ACME_CERTIFIED_KEY.write() {
        *g = None
    }
    Ok(())
}

/// Get the tls server config for actix
pub fn server_config() -> ServerConfig {
    // create the certificate in the background, it doesn't have to be immediatly present for ActiX to start.
    tokio::task::spawn_blocking(|| {
        if let Err(e) = update_certs() {
            warn!("Failed to update certificates: {:?}", e);
        }
    });
    let mut config = ServerConfig::new(rustls_18::NoClientAuth::new());
    config.cert_resolver = Arc::new(CertResolver {});
    config
}

/// Returns the secure dns name for this controller.
/// Will return `None` if no certificate has been issued yet, or the domain is not resolved to be this controller's ip.
pub fn secure_name() -> Option<String> {
    if let Ok(Some(_)) = ACCOUNT.certificate(&DOMAIN) {
        if let Ok(ifs) = get_if_addrs() {
            if let Ok(resolved) = (DOMAIN.as_str(), 443u16).to_socket_addrs() {
                for resolved in resolved {
                    for interf in &ifs {
                        if interf.ip() == resolved.ip() {
                            return Some(DOMAIN.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod test {
    use super::CertId;

    #[test]
    fn test_certid() {
        assert_eq!(CertId::new(&[12u8]).0, "z9t6h6bfeuuki0ukgbda");
        assert_eq!(CertId::new(&[128u8, 17u8, 5u8]).0, "crd8hajcagwy439c4jv1");
    }
}
