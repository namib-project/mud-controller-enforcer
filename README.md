# NAMIB MUD Controller

The MUD Controller Software manages enforcers by advertising itself via dns-sd on the local network. 
It controls firewall configurations for IoT Devices inside the network and can parse MUD files sent in DHCP requests.

## Running with docker

Download the docker-compose.yml under `docker/docker-compose.yml` and start the controller with `docker-compose up namib_mud_controller`

## Project Setup

Clone the meta project, this will checkout all of our repositories
```sh
git clone --recurse-submodules git@gitlab.informatik.uni-bremen.de:namib/mud-controller-enforcer/controller-enforcer-metaproject.git namib
```

### [Install Rust](https://rustup.rs/)

### Setup on *nix and WSL2

Install required packages:
```
sudo apt update && sudo apt install libavahi-compat-libdnssd-dev cmake clang libssl-dev libsqlite3-dev
```

**WSL2 Only: Start avahi service**
WSL2 does not run any services by default
```
sudo service dbus start
sudo service avahi-daemon start
```

### Setup on Windows

We recommend using WSL2, but if you want to set it up for development under windows, keep reading.

Get Bonjour SDK <https://developer.apple.com/bonjour/>

Get vcpkg <https://github.com/microsoft/vcpkg#quick-start-windows>

```
vcpkg install libpq sqlite3
```

Add the following Environment variables:

Variable | Value
--- | ---
PATH | ...\vcpkg\installed\x86-windows\bin
PG_LIB_DIR | ...\vcpkg\installed\x86-windows\lib
SQLITE3_LIB_DIR | ...\vcpkg\installed\x86-windows\lib
BONJOUR_SDK_HOME | C:\Program Files\Bonjour SDK

Replace `...\vcpkg` with your vcpk install location

<https://www.architectryan.com/2018/08/31/how-to-change-environment-variables-on-windows-10/>

## Running

Check the environment variables under `.env`

`cargo run`

## Testing

`cargo test`

with logs:

`RUST_LOG=debug cargo test -- --show-output`

## Scripts

Download the frontend assets
```sh
./scripts/download_namib_frontend.sh
```

Import some mock data, supports importing into sqlite, postgres and docker.
```sh
./scripts/import_mock_data.sh
```

Recreate the database by dropping it
```sh
./scripts/recreate_db.sh
```

Update the sqlx offline data for faster compilation
```sh
./scripts/update_sqlx_data.sh
```

Update the neo4things-api generated code by downloading the openapi-spec from the neo4things server.

Make sure you first start the neo4things server under port 7000 (by running `docker-compose up neo4things`)
```sh
cd neo4things-api
./generate-rust-code.sh new
```