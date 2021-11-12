#!/usr/bin/env bash

cd $(dirname $0)/..

if [[ "$1" = "postgres" ]]
then DATABASE_URL=postgres://namib:namib@localhost/namib_mud_controller cargo +stable sqlx prepare -- --bin namib_mud_controller --no-default-features --features postgres
else DATABASE_URL=sqlite:db.sqlitenamib_mud_controller cargo +stable sqlx prepare -- --bin namib_mud_controller
fi