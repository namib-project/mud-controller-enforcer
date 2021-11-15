# Metaproject

## Git Secrets

### Install

```shell
sudo apt-get update && sudo apt-get install git-secret -y 
```

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

|    Name    |     Email Address    |                GitHub Username               |
|:----------:|:--------------------:|:--------------------------------------------:|
| Hugo Damer | hdamer@uni-bremen.de | [@pulsastrix](https://github.com/pulsastrix) |
