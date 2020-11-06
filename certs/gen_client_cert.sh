#!/usr/bin/env bash

set -ex

openssl genrsa -out ../../namib_enforcer/client-key.pem 4096
openssl req -new -key ../namib_enforcer/client-key.pem -config client.cnf -out client.csr
openssl x509 -req -in client.csr -days 3650 -CA ca.pem -CAkey ca-key.pem -CAcreateserial -extfile client.cnf -extensions usr_cert -out ../namib_enforcer/client.pem