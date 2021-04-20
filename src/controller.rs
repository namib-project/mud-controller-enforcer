use std::{
    env,
    future::Future,
    net::{SocketAddr, SocketAddrV6, TcpListener},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use actix_cors::Cors;
use actix_ratelimit::{errors::ARError, MemoryStore, MemoryStoreActor, RateLimiter};
use actix_web::{
    body::MessageBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    middleware, App, HttpServer,
};
use derive_builder::Builder;
use futures::{future, future::Ready};
use paperclip::actix::{web, OpenApiExt};
use pin_project::pin_project;
use tokio::{
    sync::{oneshot, oneshot::error::RecvError},
    task::{JoinError, JoinHandle},
};

use crate::{db::DbConnection, error, error::Result, routes, services::acme_service};

const BACKLOG: i32 = 2048;

#[pin_project]
#[derive(Debug)]
pub struct ControllerAppWrapper {
    stop_server_send: oneshot::Sender<()>,
    #[pin]
    server_join_handle: JoinHandle<Result<()>>,
}

#[derive(Builder)]
#[builder]
pub struct ControllerApp {
    pub conn: DbConnection,
    #[builder(default)]
    pub http_addrs: Vec<SocketAddr>,
    #[builder(default)]
    pub https_addrs: Vec<SocketAddr>,
    #[builder(default = "num_cpus::get()")]
    pub worker_count: usize,
}

impl ControllerAppBuilder {
    pub async fn start(&self) -> std::result::Result<ControllerAppWrapper, (RecvError, ControllerAppWrapper)> {
        let controller_app = self.build().expect("Invalid app config");
        let (end_server_send, stop_server_recv) = oneshot::channel();
        let (startup_finish_send, startup_finish_recv) = oneshot::channel();
        let tokio_handle = tokio::runtime::Handle::current();
        let server_join_handle = tokio::task::spawn_blocking(move || {
            start_app(
                controller_app.conn,
                stop_server_recv,
                controller_app.http_addrs,
                controller_app.https_addrs,
                controller_app.worker_count,
                startup_finish_send,
                tokio_handle,
            )
        });
        let wrapper = ControllerAppWrapper {
            stop_server_send: end_server_send,
            server_join_handle,
        };
        if let Err(e) = startup_finish_recv.await {
            return Err((e, wrapper));
        }
        Ok(wrapper)
    }
}

impl ControllerAppWrapper {
    pub async fn stop_server(self) -> Result<()> {
        self.stop_server_send.send(()).map_err(|_| error::none_error())?;
        self.server_join_handle.await??;
        Ok(())
    }
}

impl Future for ControllerAppWrapper {
    type Output = std::result::Result<Result<()>, JoinError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().server_join_handle.poll(cx)
    }
}

pub fn start_app(
    conn: DbConnection,
    stop_server_recv: oneshot::Receiver<()>,
    http_addrs: Vec<SocketAddr>,
    https_addrs: Vec<SocketAddr>,
    worker_count: usize,
    startup_finished_send: oneshot::Sender<()>,
    tokio_handle: tokio::runtime::Handle,
) -> Result<()> {
    actix_web::rt::System::new("main").block_on(async move {
        let mut server = HttpServer::new(move || {
            let cors = Cors::default()
                .allowed_origin_fn(|origin, _req_head| {
                    origin.as_bytes().starts_with(b"https://localhost:")
                        || origin.as_bytes().starts_with(b"http://localhost:")
                        || origin
                            .as_bytes()
                            .starts_with(format!("https://{}", *acme_service::DOMAIN).as_bytes())
                        || origin
                            .as_bytes()
                            .starts_with(format!("http://{}", *acme_service::DOMAIN).as_bytes())
                })
                .allow_any_method()
                .allow_any_header()
                .max_age(3600);
            let rate_limiter = RateLimiter::new(MemoryStoreActor::from(MemoryStore::new()).start())
                .with_interval(Duration::from_secs(60))
                .with_max_requests(
                    env::var("RATELIMITER_REQUESTS_PER_MINUTE")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(120),
                )
                .with_identifier(|req| {
                    let connection_info = req.connection_info();

                    // Setup optional reverse-proxy measures and strip the port from the IP
                    // Will be changed in v0.4, more info: https://github.com/TerminalWitchcraft/actix-ratelimit/issues/15
                    let ip = if env::var("RATELIMITER_BEHIND_REVERSE_PROXY").as_deref() == Ok("true") {
                        connection_info.realip_remote_addr()
                    } else {
                        connection_info.remote_addr()
                    }
                    .ok_or(ARError::IdentificationError)?;

                    let ip_parts: Vec<&str> = ip.split(':').collect();
                    Ok(ip_parts[0].to_string())
                });

            App::new()
                .data(conn.clone())
                .wrap(cors)
                .wrap(middleware::Logger::default())
                .wrap(rate_limiter)
                .wrap(TokioWrapper(tokio_handle.clone()))
                .wrap_api()
                .service(web::scope("/status").configure(routes::status_controller::init))
                .service(web::scope("/users").configure(routes::users_controller::init))
                .service(web::scope("/management/users").configure(routes::users_management_controller::init))
                .service(web::scope("/devices").configure(routes::device_controller::init))
                .service(web::scope("/mud").configure(routes::mud_controller::init))
                .service(web::scope("/config").configure(routes::config_controller::init))
                .service(web::scope("/roles").configure(routes::role_manager_controller::init))
                .service(web::scope("/rooms").configure(routes::room_controller::init))
                .with_json_spec_at("/api/spec")
                .build()
                .route(
                    "/",
                    web::to(|| {
                        web::HttpResponse::PermanentRedirect()
                            .header("Location", "/app")
                            .finish()
                    }),
                )
                .service(
                    actix_files::Files::new("/", "static")
                        .index_file("index.html")
                        .redirect_to_slash_directory(),
                )
        })
        .workers(worker_count)
        .backlog(BACKLOG);
        // Some unix variants automatically bind to IPv4 as well when binding to IPv6
        // (Linux makes it configurable using /proc/sys/net/ipv6/bindv6only), therefore
        // causing "address already in use" errors if both IPv4 and IPv6 SockAddrs are specified.
        // This behaviour is specified to be the default for the sockets interface as per RFC 3493
        // (section 5.3).
        // To fix this, we need to manually create a socket and set the IPV6_V6ONLY socket option.
        // We use socket2 for this here, because it is the library that actix uses internally.

        // We need to set this explicitly, because we might not know if this default will change in
        // the future and it should match the setting we use for our own IPv6 sockets on UNIX.
        for http_addr in http_addrs {
            if let std::net::SocketAddr::V6(v6addr) = http_addr {
                // Special handling for IPv6: Set IPV6_V6ONLY
                let listener = create_v6only_listener(v6addr)?;
                server = server.listen(listener)?;
            } else {
                server = server.bind(http_addr)?;
            }
        }
        if !https_addrs.is_empty() {
            let tls_config = acme_service::server_config();
            for https_addr in https_addrs {
                if let std::net::SocketAddr::V6(v6addr) = https_addr {
                    let listener = create_v6only_listener(v6addr)?;
                    server = server.listen_rustls(listener, tls_config.clone())?;
                } else {
                    server = server.bind_rustls(https_addr, tls_config.clone())?;
                }
            }
        }
        let server_instance = server.run();
        startup_finished_send
            .send(())
            .unwrap_or_else(|e| warn!("Could not notify caller of finished startup: {:?}", e));
        stop_server_recv
            .await
            .unwrap_or_else(|e| warn!("Error while waiting for server end signal: {:?}", e));
        server_instance.stop(true).await;
        actix_web::rt::System::current().stop();
        Ok(())
    })
}

fn create_v6only_listener(addr: SocketAddrV6) -> Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_only_v6(true)?;
    sock.set_reuse_address(true)?;
    sock.bind(&addr.into())?;
    sock.listen(BACKLOG)?;
    Ok(sock.into())
}

struct TokioWrapper(tokio::runtime::Handle);

impl<S, B> Transform<S> for TokioWrapper
where
    S: Service<Request=ServiceRequest, Response=ServiceResponse<B>, Error=actix_web::error::Error>,
    B: MessageBody,
{
    type Error = actix_web::error::Error;
    type Future = Ready<std::result::Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Transform = TokioMiddleware<S>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ok(TokioMiddleware {
            handle: self.0.clone(),
            service,
        })
    }
}

struct TokioMiddleware<S> {
    handle: tokio::runtime::Handle,
    service: S,
}

impl<S, B> Service for TokioMiddleware<S>
where
    S: Service<Request=ServiceRequest, Response=ServiceResponse<B>, Error=actix_web::error::Error>,
    B: MessageBody,
{
    type Error = actix_web::error::Error;
    type Future = TokioResponse<S>;
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;

    fn poll_ready(&mut self, ctx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&mut self, req: Self::Request) -> TokioResponse<S> {
        TokioResponse {
            borrow: self.handle.clone(),
            fut: self.service.call(req),
        }
    }
}

#[pin_project::pin_project]
pub struct TokioResponse<S>
where
    S: Service,
{
    #[pin]
    fut: S::Future,
    borrow: tokio::runtime::Handle,
}

impl<S, B> Future for TokioResponse<S>
where
    S: Service<Request=ServiceRequest, Response=ServiceResponse<B>, Error=actix_web::error::Error>,
{
    type Output = std::result::Result<ServiceResponse<B>, actix_web::error::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let _guard = self.borrow.enter();
        self.project().fut.poll(cx)
    }
}
