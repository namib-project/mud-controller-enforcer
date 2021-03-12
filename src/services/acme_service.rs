use crate::error::{self, Result};
use acme_lib::{create_p384_key, persist::FilePersist, Account, Directory, DirectoryUrl};
use base64::CharacterSet;
use lazy_static::lazy_static;
use namib_shared::open_file_with;
use reqwest::{Certificate, Identity};
use rustls_18::{
    sign::{any_ecdsa_type, CertifiedKey},
    ClientHello, ResolvesServerCert, ServerConfig,
};
use sha1::{Digest, Sha1};
use snafu::ensure;
use std::{
    env, fmt,
    fs::File,
    io::Read,
    sync::{Arc, RwLock},
};

#[derive(Clone)]
pub struct CertId(String);

impl CertId {
    pub fn new(cert: &[u8]) -> Self {
        Self(base64::encode_config(
            Sha1::digest(cert),
            base64::Config::new(CharacterSet::UrlSafe, false),
        ))
    }
}

impl fmt::Display for CertId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

pub struct CertResolver;

fn get_letsencrypt_url() -> DirectoryUrl<'static> {
    if env::var("STAGING").as_deref() == Ok("0") {
        DirectoryUrl::LetsEncrypt
    } else {
        DirectoryUrl::LetsEncryptStaging
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
    static ref DOMAIN: String = format!("{}.{}", *SERVER_ID, env::var("DOMAIN").expect("DOMAIN was not defined"));
    /// store the CertifiedKey to not recreate it on every request
    static ref ACME_CERTIFIED_KEY: RwLock<Option<CertifiedKey>> = RwLock::new(None);
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<CertifiedKey> {
        if let Ok(g) = ACME_CERTIFIED_KEY.read() {
            if let Some(ref c) = *g {
                return Some(c.clone());
            }
        }
        let cert = match ACCOUNT.certificate(&*DOMAIN) {
            Ok(Some(c)) => CertifiedKey::new(
                vec![rustls_18::Certificate(c.certificate_der())],
                Arc::new(match any_ecdsa_type(&rustls_18::PrivateKey(c.private_key_der())) {
                    Ok(key) => key,
                    _ => return None,
                }),
            ),
            _ => return None,
        };
        if let Ok(mut g) = ACME_CERTIFIED_KEY.write() {
            *g = Some(cert.clone());
        }
        Some(cert)
    }
}

pub fn update_certs() -> Result<()> {
    debug!("checking if a certificate exists");
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
            break csr;
        }

        let auths = order.authorizations()?;
        let chall = auths[0].http_challenge();
        debug!("got http challenge: {}", chall.http_token());
        let mut certs: Vec<u8> = Vec::new();
        // The server certificate for communicating with namib services
        File::open("certs/server.pem")?.read_to_end(&mut certs)?;
        // The private key for the server certificate
        File::open("certs/server-key.pem")?.read_to_end(&mut certs)?;
        let mut ca: Vec<u8> = Vec::new();
        File::open(&env::var("NAMIB_CA_CERT").expect("NAMIB_CA_CERT env is missing"))?.read_to_end(&mut ca)?;
        let response = reqwest::blocking::ClientBuilder::new()
            .add_root_certificate(Certificate::from_pem(&ca)?)
            .identity(Identity::from_pem(&certs)?)
            .build()?
            .post(format!(
                "https://{}/.well-known/acme-challenge/{}",
                *DOMAIN,
                chall.http_token()
            ))
            .body(chall.http_proof())
            .send()?;
        ensure!(response.text()? == "ok", error::NoneError {});
        chall.validate(5000)?;
        order.refresh()?;
    };
    // create a private key for the certificate
    let pkey = create_p384_key();
    // finalize the csr using the pkey and download the certificate
    csr.finalize_pkey(pkey, 5000)?.download_and_save_cert()?;
    // make the resolver reload the certificate
    if let Ok(mut g) = ACME_CERTIFIED_KEY.write() {
        *g = None
    }
    Ok(())
}

pub fn server_config() -> ServerConfig {
    actix_rt::spawn(async {
        if let Err(e) = update_certs() {
            warn!("Failed to update certificates: {:?}", e);
        }
    });
    let mut config = ServerConfig::new(rustls_18::NoClientAuth::new());
    config.cert_resolver = Arc::new(CertResolver {});
    config
}
