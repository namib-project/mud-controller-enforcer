# NAMIB Enforcer

The Enforcer Software is designed to run on an OpenWRT operating system to enforce the configuration provided by the [NAMIB Controller](https://github.com/namib-project/namib_mud_controller).
It looks for a MUD Controller in the local network via dns-sd. 

## Installation

Public installation packages are provided [on GitHub](https://github.com/namib-project/namib_enforcer/releases).

To install the enforcer on a device running OpenWRT, download the appropiate `namib` and `dnsmasq_full` packages from the releases page, copy them to your device (e.g. using `scp`) and run `opkg install [FILENAME]` on both of them.
The `dnsmasq_full` package contains a patched version of `dnsmasq` which adds necessary features for the enforcer to correctly detect devices.
The source code for this package can be found [here](https://github.com/namib-project/dnsmasq)

After installation, you might want to validate that the CA cert and enforcer key pair are correct (for example, if you use your own keys). These are located in the `/etc/namib` directory.

The enforcer is run as a service called `namib` that can be started or stopped on demand, either using the command line (`/etc/init.d/namib [start|stop|restart]`) or another interface (like LuCI). 
By default, this service will be started with the operating system.

## Project Setup

Clone the meta project, this will checkout all of our repositories
```sh
git clone --recurse-submodules git@gitlab.informatik.uni-bremen.de:namib/mud-controller-enforcer/controller-enforcer-metaproject.git namib
```

## Running

Check the environment variables under `.env`

`cargo run`

## Testing

`cargo test`

with logs:

`RUST_LOG=debug cargo test -- --show-output`

## License

The Makefile under openwrt/package is licensed under GPLv2 as noted in its header.

The dnsmasq packages are licensed under GPLv3, for more information check https://thekelleys.org.uk/dnsmasq/doc.html

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
