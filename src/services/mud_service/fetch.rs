use crate::{error, error::Result};
use encoding_rs::{CoderResult, Encoding, UTF_8};
use mime::Mime;
use reqwest::redirect::Policy;
use snafu::ensure;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(15);
const MAX_REDIRECTS: usize = 5;
const MAX_LEN: usize = 10_000_000;

/// Fetch MUD-URL Data respecting timeout, redirects and maximum response length
pub async fn fetch_mud(url: &str) -> Result<String> {
    // start the response
    let mut response = reqwest::Client::builder()
        .redirect(Policy::limited(MAX_REDIRECTS))
        .timeout(TIMEOUT)
        .build()?
        .get(url)
        .send()
        .await?;
    // try to get the content type
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<Mime>().ok());
    // get the charset from content type or use utf-8
    let encoding_name = content_type
        .as_ref()
        .and_then(|mime| mime.get_param("charset").map(|charset| charset.as_str()))
        .unwrap_or("utf-8");
    // iterate over the chunks in the response, decoding them and aborting if the MAX_LEN is exceeded
    // adapted from https://docs.rs/encoding_rs/0.8.28/encoding_rs/
    let encoding = Encoding::for_label(encoding_name.as_bytes()).unwrap_or(UTF_8);
    let mut decoder = encoding.new_decoder();
    let mut output = String::new();
    let mut buffer_bytes = [0u8; 2048];
    let mut bytes_in_buffer = 0usize;
    let buffer: &mut str = std::str::from_utf8_mut(&mut buffer_bytes[..]).unwrap();
    while let Some(chunk) = response.chunk().await? {
        ensure!(output.len() + chunk.len() < MAX_LEN, error::MudFileInvalid);
        let mut total_read_from_current_input = 0usize;
        loop {
            let (result, read, written, had_errors) = decoder.decode_to_str(
                &chunk[total_read_from_current_input..],
                &mut buffer[bytes_in_buffer..],
                false,
            );
            ensure!(!had_errors, error::MudFileInvalid);
            total_read_from_current_input += read;
            bytes_in_buffer += written;
            match result {
                CoderResult::InputEmpty => {
                    break;
                },
                CoderResult::OutputFull => {
                    output.push_str(&buffer[..bytes_in_buffer]);
                    bytes_in_buffer = 0usize;
                    continue;
                },
            }
        }
    }
    loop {
        let (result, _, written, had_errors) = decoder.decode_to_str(b"", &mut buffer[bytes_in_buffer..], true);
        ensure!(!had_errors, error::MudFileInvalid);
        bytes_in_buffer += written;
        output.push_str(&buffer[..bytes_in_buffer]);
        bytes_in_buffer = 0usize;
        match result {
            CoderResult::InputEmpty => {
                break;
            },
            CoderResult::OutputFull => {
                continue;
            },
        }
    }
    Ok(output)
}
