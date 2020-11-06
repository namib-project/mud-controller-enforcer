#!/usr/bin/env bash

set -ex

openssl genrsa -out ../namib_mud_controller/server-key.pem 4096
openssl req -new -key ../namib_mud_controller/server-key.pem -config server.cnf -out server.csr
openssl x509 -req -in server.csr -days 3650 -CA ca.pem -CAkey ca-key.pem -CAcreateserial -extfile server.cnf -extensions server_cert -out ../namib_mud_controller/server.pem