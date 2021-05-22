# NAMIB MUD Controller

The MUD Controller Software manages enforcers by advertising itself via dns-sd on the local network. 
It controls firewall configurations for IoT Devices inside the network and can parse MUD files sent in DHCP requests.

## Running with docker

Download the docker-compose.yml under `docker/docker-compose.yml` and start the controller with `docker-compose up namib_mud_controller`

## Installing on Debian/Ubuntu

Install the Debian package provided by the CI by running `sudo apt install [PATH TO DEB FILE]`. 
You might want to change some configuration settings under `/etc/namib/config`.
The controller will be installed as a systemd service with the name `namib-mud-controller.service` and will run using a new user called
`namib-controller`.
If you prefer using postgres instead of sqlite, use the `namib-mud-controller-postgres` package from the CI instead.

## Running natively on *nix
1. Install avahi-daemon

    ```
    sudo apt update && sudo apt install avahi-daemon
    ```
   **WSL2 only: start the avahi-daemon**
   WSL2 does not run any services by default
    ```
    sudo service dbus start
    sudo service avahi-daemon start
    ```

2. [Download the latest release artifacts](https://gitlab.informatik.uni-bremen.de/namib/mud-controller-enforcer/namib_mud_controller/-/pipelines) (from the `build-release` job)

3. Unzip the artifacts and move the `bin/install/namib_mud_controller` into the root
4. Create a `.env` File with the following content:
    ```
    DATABASE_URL=sqlite:db.sqlite
    RUST_LOG=info,namib_mud_controller=debug,sqlx::query=warn,tarpc::server=warn
    NAMIB_CA_CERT=certs/namib-ca.pem
    RATELIMITER_BEHIND_REVERSE_PROXY=false
    RATELIMITER_REQUESTS_PER_MINUTE=120
    GLOBAL_NAMIB_CA_CERT=certs/namib-ca.pem
    DOMAIN=staging.namib.me
    STAGING=true
    NEO4THINGS_URL=http://localhost:7000
    NEO4THINGS_USER=admin
    NEO4THINGS_PASS=namib
    HTTP_PORT=8000
    HTTPS_PORT=9000
    RPC_PORT=8734
    ```
5. Start the `namib_mud_controller`.
   You should now be able to access the frontend under [http://localhost:8000/](http://localhost:8000/)

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

## License

The debian package postinstall-script in debian/postinst is licensed under GPL-2.0-or-later as indicated by the copyright file.

All other files are licensed under either of

* Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license
  ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

