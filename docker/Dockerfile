FROM debian:bullseye-slim

ENV RUST_LOG=info,namib_mud_controller=debug \
    JWT_SECRET=VsRunGxd5JaiGip1KI9wtMpAWJySxtpaAwM6nialtWg+FpXVtQcjoKz4S4icx+1QZ3OxAw00l7++0N+SiYn2J7B1hF4xXuMyltyphCI2RmDcdI7QhEK6oOdscezHaVzxhcSgsQ== \
    NAMIB_CA_CERT=certs/namib-ca.pem \
    GLOBAL_NAMIB_CA_CERT=certs/namib-ca.pem \
    DOMAIN=controller.namib.me \
    STAGING=0 \
    NEO4THINGS_URL=http://neo4things:8000 \
    NEO4THINGS_USER=admin \
    NEO4THINGS_PASS=namib

WORKDIR /namib

RUN apt update \
        && apt install -y avahi-daemon libavahi-compat-libdnssd1 libsqlite3-0 sqlite3 postgresql-client ca-certificates \
        && rm -rf /var/lib/apt/lists/* \
        && mkdir acme

COPY ./docker/QuoVadis_Global_SSL_ICA_G3.crt /usr/local/share/ca-certificates/QuoVadis_Global_SSL_ICA_G3.crt

RUN update-ca-certificates

COPY docker/run_mud_controller.sh run_mud_controller.sh
COPY ./install/bin/namib_mud_controller namib_mud_controller
COPY ./certs ./static db.sqlite* ./

CMD ["/namib/run_mud_controller.sh"]
