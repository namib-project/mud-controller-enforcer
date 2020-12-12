FROM debian:bullseye-slim

WORKDIR ./namib_workdir
RUN apt update && apt install -y avahi-daemon libavahi-compat-libdnssd1 libsqlite3-0
RUN ls
COPY ./install/bin/namib_mud_controller namib_mud_controller
COPY ./certs certs
COPY ./.env .env
COPY ./namib_shared/certs/ca.pem /namib_shared/certs/ca.pem
RUN echo -e '#!/bin/sh \nservice dbus start \nservice avahi-daemon start \n./namib_mud_controller' > run_mud_controller.sh
RUN chmod +x namib_mud_controller run_mud_controller.sh

CMD ["sh", "/namib_workdir/run_mud_controller.sh"]
