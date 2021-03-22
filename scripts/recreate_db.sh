#!/usr/bin/env bash

cd $(dirname $(realpath $0))/..
rm db.sqlite
sqlx db create
sqlx migrate --source migrations/sqlite run