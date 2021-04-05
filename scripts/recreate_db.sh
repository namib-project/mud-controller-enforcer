#!/usr/bin/env bash

cd $(dirname $(realpath $0))/..

MIGRATION_DIRECTORY=${MIGRATION_DIRECTORY:-migrations/sqlite}

sqlx db drop -y
sqlx db create
sqlx migrate --source $MIGRATION_DIRECTORY run