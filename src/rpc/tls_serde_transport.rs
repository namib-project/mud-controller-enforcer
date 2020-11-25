use std::{
    future::Future,
    io,
    marker::PhantomData,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::ready;
use pin_project::pin_project;
use serde::{Deserialize, Serialize};
use tarpc::serde_transport::{self, Transport};
use tokio::net::TcpStream;
use tokio_rustls::{rustls, webpki::DNSNameRef, TlsConnector};
use tokio_serde::{Deserializer, Serializer};
use tokio_util::codec::{length_delimited, length_delimited::LengthDelimitedCodec};

/// A connection Future that also exposes the length-delimited framing config.
#[pin_project]
pub struct Connect<T, Item, SinkItem, CodecFn> {
    #[pin]
    inner: T,
    #[pin]
    pending_conn: Option<tokio_rustls::Connect<TcpStream>>,
    codec_fn: CodecFn,
    config: length_delimited::Builder,
    ghost: PhantomData<(SinkItem, Item)>,
}

impl<T, Item, SinkItem, Codec, CodecFn> Future for Connect<T, Item, SinkItem, CodecFn>
where
    T: Future<Output=io::Result<tokio_rustls::Connect<TcpStream>>>,
    Item: for<'de> Deserialize<'de>,
    SinkItem: Serialize,
    Codec: Serializer<SinkItem>+Deserializer<Item>,
    CodecFn: Fn() -> Codec,
{
    type Output = io::Result<Transport<tokio_rustls::client::TlsStream<TcpStream>, Item, SinkItem, Codec>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let mut this = self.project();

        Poll::Ready(loop {
            if let Some(connect) = this.pending_conn.as_mut().as_pin_mut() {
                let io: tokio_rustls::client::TlsStream<TcpStream> = ready!(connect.poll(cx))?;
                this.pending_conn.set(None);

                break Ok(serde_transport::new(this.config.new_framed(io), (this.codec_fn)()));
            } else {
                let conn: tokio_rustls::Connect<TcpStream> = ready!(this.inner.as_mut().poll(cx))?;

                this.pending_conn.set(Some(conn));
            }
        })
    }
}

impl<T, Item, SinkItem, CodecFn> Connect<T, Item, SinkItem, CodecFn> {
    /// Returns an immutable reference to the length-delimited codec's config.
    pub fn config(&self) -> &length_delimited::Builder {
        &self.config
    }

    /// Returns a mutable reference to the length-delimited codec's config.
    pub fn config_mut(&mut self) -> &mut length_delimited::Builder {
        &mut self.config
    }
}

/// Connects to `addr`, wrapping the connection in a TLS transport.
pub fn connect<Item, SinkItem, Codec, CodecFn>(
    config: Arc<rustls::ClientConfig>,
    domain: DNSNameRef<'static>,
    addr: SocketAddr,
    codec_fn: CodecFn,
) -> Connect<impl Future<Output=io::Result<tokio_rustls::Connect<TcpStream>>>, Item, SinkItem, CodecFn>
where
    Item: for<'de> Deserialize<'de>,
    SinkItem: Serialize,
    Codec: Serializer<SinkItem>+Deserializer<Item>,
    CodecFn: Fn() -> Codec,
{
    async fn create_connector(config: Arc<rustls::ClientConfig>, domain: DNSNameRef<'static>, addr: SocketAddr) -> io::Result<tokio_rustls::Connect<TcpStream>> {
        let connector = TlsConnector::from(config);
        Ok(connector.connect(domain, TcpStream::connect(addr).await?))
    }

    Connect {
        inner: create_connector(config, domain, addr),
        pending_conn: None,
        codec_fn,
        config: LengthDelimitedCodec::builder(),
        ghost: PhantomData,
    }
}
