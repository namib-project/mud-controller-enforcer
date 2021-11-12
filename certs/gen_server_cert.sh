#!/usr/bin/env bash

set -ex

CA=${1:-ca} # default to ca.pem/ca-key.pem if not specified
CONTROLLER_PATH=${2:-../namib_mud_controller} # default
openssl genrsa -out $CONTROLLER_PATH/certs/server-key.pem 4096
openssl req -new -key $CONTROLLER_PATH/certs/server-key.pem -config server.cnf -out server.csr
openssl x509 -req -in server.csr -days 3650 -CA ${CA}.pem -CAkey ${CA}-key.pem -CAcreateserial -extfile server.cnf -extensions server_cert -out $CONTROLLER_PATH/certs/server.pem