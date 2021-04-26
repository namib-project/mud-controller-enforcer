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