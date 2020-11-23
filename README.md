# NAMIB MUD Controller

The MUD Controller Software manages enforcers by advertising itself via dns-sd on the local network. 
It controls firewall configurations for IoT Devices inside the network and can parse MUD files sent in DHCP requests.

## Project Setup

[Guide available in the namib_shared repository](https://gitlab.informatik.uni-bremen.de/namib/mud-controller-enforcer/namib_shared)

## Running

Make sure you are using nightly rust (`rustup override set nightly`)

`cargo run`

## Testing

`cargo test`

with logs:

`RUST_LOG=debug cargo test --show-output`