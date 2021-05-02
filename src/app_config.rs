use lazy_static::lazy_static;

lazy_static! {
    pub static ref APP_CONFIG: AppConfig = envy::from_env::<AppConfig>().expect("Missing environment variables");
}

/// Holds the application configuration passed in via environment variables.
#[derive(Deserialize, Debug)]
pub struct AppConfig {
    /// `RATELIMITER_REQUESTS_PER_MINUTE`: How many requests a single IP address can make per minute (default `120`).
    #[serde(default = "default_ratelimiter_requests_per_minute")]
    pub ratelimiter_requests_per_minute: usize,
    /// `RATELIMITER_BEHIND_REVERSE_PROXY`: If the app should use the `X-Forwarded-For` header to determine the client's IP address (default `false`).
    #[serde(default = "default_ratelimiter_behind_reverse_proxy")]
    pub ratelimiter_behind_reverse_proxy: bool,
    /// `JWT_SECRET`: The base64 encoded jwt secret (with + and /) used for token de- and encryption.
    pub jwt_secret: String,
    /// `DATABASE_URL`: The postgres (`postgres://..`) or sqlite (`sqlite:db.sqlite`) url to connect to.
    pub database_url: String,
    /// `HTTP_PORT`: The port to use for the http server (default `8000`)
    #[serde(default = "default_http_port")]
    pub http_port: u16,
    /// `HTTPS_PORT`: The port to use for the https server (default `9000`)
    #[serde(default = "default_https_port")]
    pub https_port: u16,
    /// `RPC_PORT`: The port to use for the rpc server (default `8734`).
    #[serde(default = "default_rpc_port")]
    pub rpc_port: u16,
    /// `NAMIB_CA_CERT`: The path to the NAMIB CA Certificate to use for client verification.
    pub namib_ca_cert: String,
    /// `NAMIB_SERVER_CERT`: The path to the NAMIB server certificate to use for client identification.
    #[serde(default = "default_server_cert")]
    pub namib_server_cert: String,
    /// `NAMIB_SERVER_KEY`: The path to the NAMIB server key to use for client identification.
    #[serde(default = "default_server_key")]
    pub namib_server_key: String,
    /// `GLOBAL_NAMIB_CA_CERT`: The path to the Global NAMIB CA Certificate used to verify the httpchallenge service.
    /// This only differs from `NAMIB_CA_CERT` if using the staging environment.
    pub global_namib_ca_cert: String,
    /// `DOMAIN`: The domain the NAMIB Service is running under, e.g. `controller.namib.me`.
    pub domain: String,
    /// `STAGING`: Whether to use the staging environment (default `true`).
    #[serde(default = "default_is_staging")]
    pub staging: bool,
    /// `NEO4THINGS_URL`: The url the neo4things service is available under.
    pub neo4things_url: String,
    /// `NEO4THINGS_USER`: The user for neo4things authentication.
    pub neo4things_user: String,
    /// `NEO4THINGS_USER`: The password for neo4things authentication.
    pub neo4things_pass: String,
    /// `NAMIB_ACME_DIR`: The directory that ACME generated certs (letsencrypt certs) are saved
    #[serde(default = "default_acme_dir")]
    pub namib_acme_dir: String,
}

fn default_ratelimiter_requests_per_minute() -> usize {
    120
}

fn default_ratelimiter_behind_reverse_proxy() -> bool {
    false
}

fn default_http_port() -> u16 {
    8000
}

fn default_https_port() -> u16 {
    9000
}

fn default_rpc_port() -> u16 {
    8734
}

fn default_is_staging() -> bool {
    true
}

fn default_acme_dir() -> String {
    "./acme".to_string()
}

fn default_server_cert() -> String {
    "./certs/server.pem".to_string()
}
fn default_server_key() -> String {
    "./certs/server-key.pem".to_string()
}
