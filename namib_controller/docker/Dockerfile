FROM debian:bullseye-slim

ENV RUST_LOG=info,namib_mud_controller=debug \
    JWT_SECRET=VsRunGxd5JaiGip1KI9wtMpAWJySxtpaAwM6nialtWg+FpXVtQcjoKz4S4icx+1QZ3OxAw00l7++0N+SiYn2J7B1hF4xXuMyltyphCI2RmDcdI7QhEK6oOdscezHaVzxhcSgsQ== \
    NAMIB_CA_CERT=certs/namib-ca.pem \
    GLOBAL_NAMIB_CA_CERT=certs/namib-ca.pem \
    DOMAIN=controller.namib.me \
    STAGING=false \
    NEO4THINGS_URL=http://neo4things:8000 \
    NEO4THINGS_USER=admin \
    NEO4THINGS_PASS=namib

WORKDIR /namib

RUN apt-get update \
        && apt-get install -y avahi-daemon libavahi-compat-libdnssd1 libsqlite3-0 sqlite3 postgresql-client ca-certificates \
        && mkdir acme

COPY ./namib_controller/docker/QuoVadis_Global_SSL_ICA_G3.crt /usr/local/share/ca-certificates/QuoVadis_Global_SSL_ICA_G3.crt

RUN update-ca-certificates

COPY ./namib_controller/docker/run_mud_controller.sh db.sqlite* ./
COPY ./namib_controller/install/bin/namib_controller namib_controller
COPY ./namib_controller/certs certs
COPY ./namib_controller/static static

CMD ["/namib/run_mud_controller.sh"]
