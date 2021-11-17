#!/usr/bin/env bash

MIGRATION_DIRECTORY=${MIGRATION_DIRECTORY:-$(dirname $0)/../migrations/sqlite}

sqlx db drop -y
sqlx db create
sqlx migrate --source $MIGRATION_DIRECTORY run