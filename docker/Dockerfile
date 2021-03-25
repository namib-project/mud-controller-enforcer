FROM debian:bullseye-slim

ENV RUST_LOG=info,namib_mud_controller=debug \
    JWT_SECRET=VsRunGxd5JaiGip1KI9wtMpAWJySxtpaAwM6nialtWg+FpXVtQcjoKz4S4icx+1QZ3OxAw00l7++0N+SiYn2J7B1hF4xXuMyltyphCI2RmDcdI7QhEK6oOdscezHaVzxhcSgsQ== \
    NAMIB_CA_CERT=certs/namib-ca.pem \
    GLOBAL_NAMIB_CA_CERT=certs/namib-ca.pem \
    DOMAIN=controller.namib.me \
    STAGING=0

WORKDIR /namib

RUN apt update \
        && apt install -y avahi-daemon libavahi-compat-libdnssd1 \
        && rm -rf /var/lib/apt/lists/* \
        && mkdir acme

COPY docker/run_mud_controller.sh run_mud_controller.sh
COPY ./install/bin/namib_mud_controller namib_mud_controller
COPY ./certs certs
COPY ./static static

CMD ["/namib/run_mud_controller.sh"]
