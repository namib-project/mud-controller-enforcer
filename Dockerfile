FROM alpine:latest

COPY /install/bin/namib_mud_controller namib_mud_controller

CMD ["./namib_mud_controller"]
