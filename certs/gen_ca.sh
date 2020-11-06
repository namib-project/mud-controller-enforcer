#!/usr/bin/env bash

set -e

openssl req -new -x509 -days 3650 -config ca.cnf -keyout ca-key.pem -out ca.pem
chmod 600 ca.pem ca-key.pem