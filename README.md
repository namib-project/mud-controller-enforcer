# NAMIB Shared Repository

This is the shared library for MUD controller and enforcer. This is for sharing Rust structures for transfer of data through RPC.

## Local Setup

[Install Rust](https://rustup.rs/)

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

| PATH | ...\vcpkg\installed\x86-windows\bin |
| PG_LIB_DIR | ...\vcpkg\installed\x86-windows\lib |
| SQLITE3_LIB_DIR | ...\vcpkg\installed\x86-windows\lib |
| BONJOUR_SDK_HOME | C:\Program Files\Bonjour SDK |

Replace `...\vcpkg` with your vcpk install location

<https://www.architectryan.com/2018/08/31/how-to-change-environment-variables-on-windows-10/>

## Checkout required repositories

```
mkdir namib
cd namib
git clone git@gitlab.informatik.uni-bremen.de:namib/mud-controller-enforcer/namib_shared.git
git clone --recurse-submodules git@gitlab.informatik.uni-bremen.de:namib/mud-controller-enforcer/libuci-sys.git
git clone git@gitlab.informatik.uni-bremen.de:namib/mud-controller-enforcer/rust-async-dnssd.git
git clone git@gitlab.informatik.uni-bremen.de:namib/mud-controller-enforcer/namib_shared.git
git clone git@gitlab.informatik.uni-bremen.de:namib/mud-controller-enforcer/namib_enforcer.git
git clone git@gitlab.informatik.uni-bremen.de:namib/mud-controller-enforcer/namib_mud_controller.git

cd namib_mud_controller
rustup override set nightly
```

