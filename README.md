# yaml-crypt

Command line utility to encrypt and decrypt YAML documents.

## Installation

The package is available on the [npm registry](https://www.npmjs.com/package/yaml-crypt), so just run

    $ yarn add yaml-crypt
    $ ./node_modules/yaml-crypt/bin/yaml-crypt.js --help

You can also install the package globally: `yarn global add yaml-crypt`

## Usage

First you will need to generate a key file. Currently, only the [Fernet](https://github.com/fernet/spec/blob/master/Spec.md)
encryption scheme is supported, so you will need a key with exactly 32 bytes.
The easiest way is to use the [pwgen](https://linux.die.net/man/1/pwgen) command:

    $ pwgen 32 1 > my-key

Another way would be to use the `urandom` device file:

    $ cat /dev/urandom | LC_ALL=C tr -dc A-Za-z0-9 | head -c 32 > my-key

To encrypt all values in a YAML file, run

    $ yaml-crypt -k my-key my-file.yaml

This will generate the file `my-file.yaml-crypt`, while leaving `my-file.yaml` intact.
If you want to delete the original file after encryption, use the `--rm` option.

> Files will be deleted using [unlink](https://linux.die.net/man/2/unlink).
> If this does not meet your security needs, consider removing the file manually instead!

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

## Configuration

The yaml-crypt command looks in `~/.yaml-crypt` for a file `config.yaml` or `config.yml`.
Currently, only the `defaultKeyFile` property is supported. This key file will be used
when no key files are given on the command line:

    $ cat ~/.yaml-crypt/config.yaml
    defaultKeyFile: /home/user/.my-key
    $ yaml-crypt my-file.yaml

## License

The yaml-crypt tool is licensed under the MIT License
