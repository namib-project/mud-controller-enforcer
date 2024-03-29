# NAMIB MUD Controller and Enforcer (Monorepo)

This repository holds the NAMIB MUD Controller and Enforcer.

A Manufacturer Usage Description (MUD) is a definition format to describe the
necessary communication permissions of an IoT device by a manufacturer.
It is defined in [RFC8520](https://datatracker.ietf.org/doc/html/rfc8520).

The NAMIB MUD Controller implements a conversion of MUD to abstracted firewall
rules.
The Enforcer then applies these rules via Netfilter to the OpenWRT router on
which it runs as a service.
Together they function as a MUD-Manager per RFC8520.

## Binaries

Currently we publish no binaries, packages or images.
We plan on adding these in the near future.

## Build dependencies (Debian/Ubuntu)

```bash
sudo apt-get update && sudo apt-get install -y \
      cmake clang \
      libavahi-compat-libdnssd-dev libssl-dev \
      nftables jq sqlite3 unzip \
&& curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
&& source $HOME/.cargo/env \
&& rustup component add clippy rustfmt rust-src
```

## Build dependencies (CentOS/RHEL-like)

```bash
sudo sh -c "yum groupinstall -y 'Development Tools' \
  && yum install -y \
    cmake clang \
    avahi-compat-libdns_sd-devel openssl-devel \
    nftables jq sqlite unzip" \
&& curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
&& source $HOME/.cargo/env \
&& rustup component add clippy rustfmt rust-src
```


## Run locally for development

To build and run the NAMIB controller and enforcer locally, use the `run_local.sh` script to run the components in separate terminals.

```bash
./run_local.sh controller  # run controller in terminal 1
./run_local.sh enforcer  # run controller in terminal 2
./run_local.sh whitelist  # whitelist enforcer in database after first contact
```

The components are communicating successfully when you see this message:

> DEBUG namib_enforcer::rpc::rpc_client] Heartbeat OK!

## Git Secrets

### Add a new user

The new user has to generate a gpg key:
```
gpg --gen-key
gpg --armor --export your.email@address.com > public-key.gpg
```

Send this key to any user that has already been added, they run:

```shell
gpg --import public-key.gpg
git secret tell their.email@address.com
git secret reveal                       # decrypt
git secret hide                         # reencrypt with the new user
# ... git commit && git push
```

### Show secrets

```shell
git secret reveal
```

### Reencrypt secrets after changing them

```shell
git secret hide
```

### Adding a new secret

```shell
git secret add <filename>   # git secret automatically adds the decrypted file to .gitignore
git secret hide             # encrypt the file
# ... git commit && git push
```

## License

Licensed under either of

* Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license
  ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

## Maintainers

This project is currently maintained by the following developers:

|       Name       |     Email Address      |                 GitHub Username                  |
|:----------------:|:----------------------:|:------------------------------------------------:|
| Jan Hensel       |  ja_he@uni-bremen.de   |        [@ja-he](https://github.com/ja-he)        |
| Hannes Masuch    |   hama@uni-bremen.de   | [@HannesMasuch](https://github.com/HannesMasuch) |
| Jasper Wiegratz  | wiegratz@uni-bremen.de |         [@jwhb](https://github.com/jwhb)         |
| Hugo Damer       |  hdamer@uni-bremen.de  |   [@pulsastrix](https://github.com/pulsastrix)   |
