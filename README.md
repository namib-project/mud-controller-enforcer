# NAMIB Enforcer

The Enforcer Software is designed to run on an OpenWRT operating system.
It looks for a MUD Controller in the local network via dns-sd. 

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

The Makefile under openwrt_package is licensed under GPLv2 as noted in its header.

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
