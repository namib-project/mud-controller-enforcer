FROM debian:bullseye-slim

ENV DATABASE_URL=db.sqlite \
    ROCKET_DATABASES={sqlite_db={url="db.sqlite"}} \
    MIGRATION_DIRECTORY=migrations/sqlite \
    RUST_LOG=info,namib_mud_controller=debug \
    JWT_ACCESS_TOKEN_SECRET=VsRunGxd5JaiGip1KI9wtMpAWJySxtpaAwM6nialtWg+FpXVtQcjoKz4S4icx+1QZ3OxAw00l7++0N+SiYn2J7B1hF4xXuMyltyphCI2RmDcdI7QhEK6oOdscezHaVzxhcSgsQ== \
    JWT_REFRESH_TOKEN_SECRET=W6h6JQ0FbqfNfTjaOtM7OPPB3MZ0SbTtm6snQm9dneKIBuT$721v!z1O9fN%zQOEAd#L&OiR$7VcjaP^JQ@YcHK1c#Tg#X%OvXvJy*GwN24Pih89v2swwSMyejHFY2#71SiVGmp \
    NAMIB_CA_CERT=certs/namib-ca.pem

WORKDIR /namib

RUN apt update && apt install -y avahi-daemon libavahi-compat-libdnssd1 libsqlite3-0

COPY docker/run_mud_controller.sh run_mud_controller.sh
COPY ./install/bin/namib_mud_controller namib_mud_controller
COPY ./certs certs

CMD ["/namib/run_mud_controller.sh"]
