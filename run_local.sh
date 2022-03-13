#!/bin/sh
# Run NAMIB stack locally.
# Usage: ./run_local.sh [enforcer|controller|whitelist]
# Copyright 2022, Jasper Wiegratz

set -e

APP_DIR=$PWD
NAMIB_DIR=/etc/namib
DOMAIN=staging.namib.me
ENFORCER_DIR=$APP_DIR/namib_enforcer
CONTROLLER_DIR=$APP_DIR/namib_controller
CONTROLLER_RUST_LOG=info,namib_controller=debug,sqlx::query=warn,tarpc::server=warn
ENFORCER_RUST_LOG=info,namib_enforcer=debug

setup_avahi() {
  # disable avahi ipv6 (TODO: remove when IPv6 discovery in enforcer is fixed)
  grep "use-ipv6=yes" /etc/avahi/avahi-daemon.conf >/dev/null 2>&1 && (
    read -p "Avahi is using IPv6. Should it be disabled now? (y/n) " answer
    case "${answer}" in 
      y|Y)
        sudo sed -i.bak -r 's/use-ipv6=yes/use-ipv6=no/' /etc/avahi/avahi-daemon.conf
        echo "Patched /etc/avahi/avahi-daemon.conf and created backup /etc/avahi/avahi-daemon.conf.bak"
        restart_service 'avahi-daemon'
        ;;
      *)
        echo "Not disabling Avahi IPv6."
        ;;
    esac
  ) || true
}

restart_service() {
  local service="${1}"
  if command -v service >/dev/null 2>&1; then
    sudo service "${service}" restart
  elif test -d /run/systemd/system; then
    sudo systemctl restart "${service}"
  else
    echo "please manually restart '${service}' on your system."
    read -p "done? ([y]es/[a]bort) > " input
    case "${input}" in
      y | yes)
        echo "continuing..."
        ;;
      a | abort | '')
        echo "aborting..."
        exit 1
        ;;
      *)
        echo "unknown command '${input}'"
        restart_service "${service}"
        ;;
    esac
  fi
}

setup_database() {
  if ! command -v sqlite3 >/dev/null 2>&1; then
      echo "ERROR: sqlite3 command missing."
      exit 1
  fi
  if ! command -v sqlx >/dev/null 2>&1; then
      echo "INFO: sqlx cli missing, installing it now."
      cargo install sqlx-cli
  fi

  (
    cd $CONTROLLER_DIR
    ls $CONTROLLER_DIR/db.sqlite >/dev/null 2>&1 \
      || scripts/recreate_db.sh
    if [ "$(sqlite3 db.sqlite 'select count(id) from devices')" = "0" ]; then
      echo "INFO: importing mock data."
      echo 0 | scripts/import_mock_data.sh
    fi
  )
}

ensure_tls() {
  ls $APP_DIR/certs/ca.pem $CONTROLLER_DIR/certs/server.pem $ENFORCER_DIR/certs/client.pem >/dev/null 2>&1 ||
    (
      cd $APP_DIR/certs
      ./gen_ca.sh
      ./gen_server_cert.sh
      ./gen_client_cert.sh
    )
}

cmd_controller() {
  ensure_tls
  setup_database

  DATABASE_URL=sqlite:$CONTROLLER_DIR/db.sqlite \
    cargo build -p namib_controller

  BIN_CONTROLLER=$PWD/target/debug/namib_controller

  ls $CONTROLLER_DIR/static/app/version.json >/dev/null 2>&1 || (
    cd $CONTROLLER_DIR
    scripts/download_namib_frontend.sh
  )

  (
    cd namib_controller && \
    DATABASE_URL=sqlite:db.sqlite \
    RUST_LOG=$CONTROLLER_RUST_LOG \
    RATELIMITER_BEHIND_REVERSE_PROXY=false \
    RATELIMITER_REQUESTS_PER_MINUTE=120 \
    NAMIB_SERVER_CERT=certs/server.pem \
    NAMIB_SERVER_KEY=certs/server-key.pem \
    NAMIB_CA_CERT=$APP_DIR/certs/ca.pem \
    GLOBAL_NAMIB_CA_CERT=$APP_DIR/certs/ca.pem \
    DOMAIN=$DOMAIN \
    STAGING=true \
    NEO4THINGS_URL=http://neo4things:8000 \
    NEO4THINGS_USER=admin \
    NEO4THINGS_PASS=namib \
    HTTP_PORT=8000 \
    HTTPS_PORT=9000 \
    RPC_PORT=8734 \
      $BIN_CONTROLLER
  )
}

cmd_enforcer() {
  ensure_tls
  setup_avahi

  ls $NAMIB_DIR >/dev/null 2>&1 || sudo mkdir -p $NAMIB_DIR
  jq '.secure_name' $NAMIB_DIR/state.json >/dev/null 2>&1 \
  || jq -n --arg namib_hostname "controller.$DOMAIN" '{
    "version": "27",
    "devices": [],
    "secure_name": $namib_hostname
  }' | sudo tee $NAMIB_DIR/state.json >/dev/null 2>&1

  cargo build -p namib_enforcer --no-default-features --features nftables

  NAMIB_IDENTITY=$ENFORCER_DIR/certs/identity.pfx \
  NAMIB_CONFIG_STATE_FILE=$NAMIB_DIR/state.json \
  NAMIB_CA_CERT=$APP_DIR/certs/ca.pem \
  RUST_LOG=$ENFORCER_RUST_LOG \
    sudo -E target/debug/namib_enforcer
}

cmd_whitelist() {
  UPDATED=`sqlite3 $CONTROLLER_DIR/db.sqlite 'update enforcers set allowed = 1; select total_changes();'`
  echo "INFO: whitelisted $UPDATED enforcers."
}

help_text() {
  echo "$0 [enforcer|controller|whitelist]"
}

arg_command=$1
case $arg_command in
  "" | "-h" | "--help")
    help_text
    ;;
  *)
    shift
    cmd_$arg_command $@
    if [ $? = 127 ]; then
      echo "$0 [enforcer|controller|whitelist]"
      exit 1
    fi
    ;;
esac
