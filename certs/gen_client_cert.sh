#!/usr/bin/env bash

set -ex

CA=${1:-ca} # default to ca.pem/ca-key.pem if not specified
ENFORCER_PATH=../namib_enforcer
openssl genrsa -out $ENFORCER_PATH/certs/client-key.pem 4096
openssl req -new -key $ENFORCER_PATH/certs/client-key.pem -config client.cnf -out client.csr
openssl x509 -req -in client.csr -days 3650 -CA ${CA}.pem -CAkey ${CA}-key.pem -CAcreateserial -extfile client.cnf -extensions usr_cert -out $ENFORCER_PATH/certs/client.pem
openssl pkcs12 -export -out $ENFORCER_PATH/certs/identity.pfx -inkey $ENFORCER_PATH/certs/client-key.pem -in $ENFORCER_PATH/certs/client.pem -password pass:client