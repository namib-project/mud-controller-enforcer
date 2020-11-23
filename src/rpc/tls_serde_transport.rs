use std::{
    future::Future,
    io,
    marker::PhantomData,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::{prelude::*, ready};
use pin_project::pin_project;
use serde::{Deserialize, Serialize};
use tarpc::serde_transport::{self, Transport};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls as rustls;
use tokio_rustls::TlsAcceptor;
use tokio_serde::{Deserializer, Serializer};
use tokio_util::codec::{length_delimited, length_delimited::LengthDelimitedCodec};

/// Listens on `addr`, wrapping accepted connections in TCP transports.
pub async fn listen<Item, SinkItem, Codec, CodecFn>(
    config: Arc<rustls::rustls::ServerConfig>,
    addr: SocketAddr,
    codec_fn: CodecFn,
) -> io::Result<Incoming<Item, SinkItem, Codec, CodecFn>>
where
    Item: for<'de> Deserialize<'de>,
    Codec: Serializer<SinkItem>+Deserializer<Item>,
    CodecFn: Fn() -> Codec,
{
    let acceptor = TlsAcceptor::from(config);
    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    Ok(Incoming {
        acceptor,
        listener,
        pending_conn: None,
        codec_fn,
        local_addr,
        config: LengthDelimitedCodec::builder(),
        ghost: PhantomData,
    })
}

/// A [`TcpListener`] that wraps connections in [transports](Transport).
#[pin_project]
pub struct Incoming<Item, SinkItem, Codec, CodecFn> {
    acceptor: rustls::TlsAcceptor,
    #[pin]
    listener: TcpListener,
    #[pin]
    pending_conn: Option<tokio_rustls::Accept<TcpStream>>,
    local_addr: SocketAddr,
    codec_fn: CodecFn,
    config: length_delimited::Builder,
    ghost: PhantomData<(Item, SinkItem, Codec)>,
}

impl<Item, SinkItem, Codec, CodecFn> Incoming<Item, SinkItem, Codec, CodecFn> {
    /// Returns the address being listened on.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns an immutable reference to the length-delimited codec's config.
    pub fn config(&self) -> &length_delimited::Builder {
        &self.config
    }

    /// Returns a mutable reference to the length-delimited codec's config.
    pub fn config_mut(&mut self) -> &mut length_delimited::Builder {
        &mut self.config
    }
}

impl<Item, SinkItem, Codec, CodecFn> Stream for Incoming<Item, SinkItem, Codec, CodecFn>
where
    Item: for<'de> Deserialize<'de>,
    SinkItem: Serialize,
    Codec: Serializer<SinkItem>+Deserializer<Item>,
    CodecFn: Fn() -> Codec,
{
    type Item = io::Result<Transport<rustls::server::TlsStream<TcpStream>, Item, SinkItem, Codec>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        Poll::Ready(loop {
            if let Some(conn) = this.pending_conn.as_mut().as_pin_mut() {
                let accepted: rustls::server::TlsStream<TcpStream> = ready!(conn.poll(cx)?);
                this.pending_conn.set(None);

                break Some(Ok(serde_transport::new(this.config.new_framed(accepted), (this.codec_fn)())));
            } else {
                let conn: TcpStream = ready!(this.listener.as_mut().poll_accept(cx)?).0;

                this.pending_conn.set(Some(this.acceptor.accept(conn)))
            }
        })
    }
}
