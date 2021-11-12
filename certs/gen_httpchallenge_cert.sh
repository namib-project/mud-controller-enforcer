#!/usr/bin/env bash

set -ex

CA=${1:-ca} # default to ca.pem/ca-key.pem if not specified
HTTPCHALL_PATH=../httpchallenge
openssl genrsa -out $HTTPCHALL_PATH/certs/httpchallenge-key.pem 4096
openssl req -new -key $HTTPCHALL_PATH/certs/httpchallenge-key.pem -config httpchallenge.cnf -out httpchallenge.csr
openssl x509 -req -in httpchallenge.csr -days 3650 -CA ${CA}.pem -CAkey ${CA}-key.pem -CAcreateserial -extfile httpchallenge.cnf -extensions server_cert -out $HTTPCHALL_PATH/certs/httpchallenge.pem