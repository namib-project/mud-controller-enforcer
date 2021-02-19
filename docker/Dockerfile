FROM debian:bullseye-slim

ENV DATABASE_URL=sqlite:db.sqlite \
    MIGRATION_DIRECTORY=migrations/sqlite \
    RUST_LOG=info,namib_mud_controller=debug \
    JWT_SECRET=VsRunGxd5JaiGip1KI9wtMpAWJySxtpaAwM6nialtWg+FpXVtQcjoKz4S4icx+1QZ3OxAw00l7++0N+SiYn2J7B1hF4xXuMyltyphCI2RmDcdI7QhEK6oOdscezHaVzxhcSgsQ== \
    NAMIB_CA_CERT=certs/namib-ca.pem

WORKDIR /namib

RUN apt update && apt install -y avahi-daemon libavahi-compat-libdnssd1 libsqlite3-0

COPY docker/run_mud_controller.sh run_mud_controller.sh
COPY ./install/bin/namib_mud_controller namib_mud_controller
COPY ./certs certs
COPY ./static static
COPY ./db.sqlite db.sqlite

CMD ["/namib/run_mud_controller.sh"]
