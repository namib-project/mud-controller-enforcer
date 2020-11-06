use dotenv::dotenv;

use error::Result;

mod error;
mod rpc;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv()?;
    env_logger::init();

    rpc::rpc_client::run().await?;

    Ok(())
}
