# yaml-crypt

[![Build Status](https://img.shields.io/travis/autoapply/yaml-crypt.svg?style=flat-square)](https://travis-ci.org/autoapply/yaml-crypt)
[![Coverage status](https://img.shields.io/coveralls/github/autoapply/yaml-crypt.svg?style=flat-square)](https://coveralls.io/github/autoapply/yaml-crypt)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)

Command line utility to encrypt and decrypt YAML documents.

## Installation

The package is available on the [npm registry](https://www.npmjs.com/package/yaml-crypt), so just run

    $ yarn global add yaml-crypt
    $ yaml-crypt --help

You can also install the package locally:

    $ mkdir yaml-crypt && cd yaml-crypt
    $ yarn init --yes
    $ yarn add yaml-crypt
    $ ./node_modules/.bin/yaml-crypt --help

## Usage

First you will need to generate a key file. Currently,
both [Fernet](https://github.com/fernet/spec/blob/master/Spec.md)
and [Branca](https://branca.io/) encryption schemes are supported.

To generate a new random key, run

    $ yaml-crypt --generate-key > my-key

To encrypt all values in a YAML file, run

    $ yaml-crypt -k my-key my-file.yaml

This will generate the file `my-file.yaml-crypt`.

The operation will be performed based on the file extension, so to decrypt a file,
just use

    $ yaml-crypt -k my-key my-file.yaml-crypt

You can also encrypt only certain parts of a file. Given the following YAML file

    apiVersion: v1
    kind: Secret
    data:
      username: user1
      password: secret123

you can use `--path data` to only encrypt the values `user1` and `secret123`.

Kubernetes secrets are Base64 encoded, so you should use the `--base64` option.

It is also possible to directly open encrypted files in an editor, decrypting them
before opening and encrypting again when saving:

    $ yaml-crypt -E my-file.yaml-crypt

## Configuration

The yaml-crypt command looks in `~/.yaml-crypt` for a file `config.yaml` or `config.yml`.
Currently, only the `keys` property is supported. These keys will be used when no keys
are given on the command line:

    $ cat ~/.yaml-crypt/config.yaml
    keys:
    - key: my-raw-key-data
    - key: !!binary my-base64-key-data
    $ yaml-crypt my-file.yaml

All whitespaces at the beginning and end of keys will be removed when reading keys.

## License

The yaml-crypt tool is licensed under the MIT License
