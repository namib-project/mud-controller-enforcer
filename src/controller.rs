use std::{env, net::SocketAddr, ops::Deref, rc::Rc, time::Duration};

use actix_cors::Cors;
use actix_ratelimit::{errors::ARError, MemoryStore, MemoryStoreActor, RateLimiter};
use actix_web::{dev::Service, middleware, App, HttpServer};
use dotenv::dotenv;
use lazy_static::{lazy_static, LazyStatic};
use paperclip::actix::{web, OpenApiExt};
use tokio::{
    select,
    sync::{oneshot, oneshot::Sender},
};

use crate::{
    db,
    db::DbConnection,
    error::Result,
    routes,
    services::{acme_service, job_service},
    VERSION,
};

lazy_static! {
    static ref RT: tokio::runtime::Handle = tokio::runtime::Handle::current();
}

pub fn app(
    conn: DbConnection,
    end_server: oneshot::Receiver<()>,
    http_addrs: Vec<SocketAddr>,
    https_addrs: Vec<SocketAddr>,
    worker_count: Option<usize>,
    finished_startup_sender: Option<oneshot::Sender<()>>,
) -> Result<()> {
    LazyStatic::initialize(&RT);
    actix_web::rt::System::new("main").block_on(async move {
        let tls_config = acme_service::server_config();
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
                .wrap_fn(|req, srv| {
                    let fut = srv.call(req);
                    async {
                        let _hand = RT.enter();
                        fut.await
                    }
                })
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
        });
        for http_addr in http_addrs {
            server = server.bind(http_addr)?;
        }
        for https_addr in https_addrs {
            server = server.bind_rustls(https_addr, tls_config.clone())?;
        }
        if let Some(worker_count) = worker_count {
            server = server.workers(worker_count);
        }
        let server_instance = server.run();
        if let Some(finished_startup_sender) = finished_startup_sender {
            finished_startup_sender
                .send(())
                .unwrap_or_else(|e| warn!("Could not notify caller of finished startup: {:?}", e));
        }
        end_server.await;
        server_instance.stop(true).await;
        actix_web::rt::System::current().stop();
        Ok(())
    })
}
