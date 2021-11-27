#!/bin/sh
service dbus start
service avahi-daemon start

# Generate a random jwt secret if necessary
[ -f jwt_secret ] || ( head /dev/urandom -c 64 | base64 -w 0 > jwt_secret )
export JWT_SECRET=$(cat jwt_secret)

exec ./namib_controller
