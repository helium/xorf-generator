[![Build Status][actions-badge]][actions-url]
[![Discord chat][discord-badge]][discord-url]

[actions-badge]: https://github.com/helium/xorf-generator/actions/workflows/rust.yml/badge.svg?branch=main
[actions-url]: https://github.com/helium/xorf-generator/actions/workflows/rust.yml
[discord-badge]: https://img.shields.io/discord/500028886025895936.svg?logo=discord&style=flat-square
[discord-url]: https://discord.gg/helium

## xorf-generator

This application is used to construct a binary filter that can be used to manage
lists of Base58 encoded public keys (like Hotspot addresses or Account public
keys). It was initially created to manage denylists in Helium Hotspots.

Given a list of public keys in a csv file, it constructs an 32 bit binary fuse
filter, signs and versions it, and produces a binary file that can be processed
by Helium Hotspots.

The signing key that is used to verify the filter has its public key included in
miner firmware builds, while its private key is managed and protected by the
build infrastructure producing the filter.

## Usage

### Build the application

Build the application using `cargo build --release` or download one of the
[release packages](https://github.com/helium/xorf-generator/releases)

### Create a multisig signing key

To create a multisig signing key create a `public_key.json` file with a list
of public keys and the minimum required number of signatures the multisig key
will allow.

Example `public_key.json` with two (test) keys where just one signature is
required:

```json
{
  "public_keys": [
    "14HZVR4bdF9QMowYxWrumcFBNfWnhDdD5XXA5za1fWwUhHxxFS1",
    "14MRZY2jc2ABDq1faCCMmXrkm2PXY9UBRTP1j9PWnFTKnCb7Hyn"
  ],
  "required": 1
}
```

**NOTE** This step is only needed to initially create, or update, the list of signing keys required, and will require a corresponding change in the consumer of the filter to adjust for a newly created multsig key.

To get info for a given multisig key:

```shell
$ xorf-generator key info
{
  "address": "1SVRdbb7Xe1ijHYwGMVx55wnmRRzwhb3jRkw5fAGr3zoaiqAq9tcLKKH",
  "keys": 2,
  "required": 1
}
```

### Generate a Manifest

Generate a manifest and signing data for a given csv file of public keys

```shell
$ xorf-generator manifest generate -i hotspots.csv --serial 1 -f
```

where the `hotspots.csv` is the list of public keys to include in the filter,
and the serial option the serial number for the signing data. This will generate
a `manifest.json` file with the hash of the signing bytes of the filter, the
serial number and a signature array entry where multisig members will add
signatures to. The `-f` option force overwrites an existing manifest output
files if specified.

### Member Signing

The required number of members in the `public_key` can sign with the helium
wallet cli for their public key.

To get the data to sign get the csv file of public keys needs to go into the
filter. This file can be from a repo/pull-request somewhere or shared through
other means. The member will also need the manifest file that is being asked to
add a signature to.

Verify the manifest against the input csv and produce the signing data:

```shell
$ xorf-generator manifest verify --input /tmp/suspicious.csv
{
  "hash": {
  "hash": "psu4MHfJV+pDHal5/CezlLUzJxXn2RpMmg5Gkv/UtOw=",
    "serial": 1,
    "verified": true
  },
  "signatures": [],
  "signing_data": "data.bin"
}
```

Assuming the manifest matches the given file of csv files a `data.bin` is
generated. The member can sign this data using:

```shell
$ helium_wallet -f <wallet.key> sign file <data.bin>
```

where wallet.key is the wallet for the member's public key and `data.bin` the signing data produced by the previous manifest command.

The resulting wallet output will need to be added to the manifest.json and
committed to a central location (like a repository), or sent to the person
manging the manifest.

### Generate the Filter

Once the required numebr of signatures is collected, the final filter can be generated using:

```shell
$ filter generate -i /tmp/suspicious.csv
{
  "address": "1SVRdbb7Xe1ijHYwGMVx55wnmRRzwhb3jRkw5fAGr3zoaiqAq9tcLKKH",
  "verified": true
}
```

which will take the (implied) `public key.json` and (implied) `manifest.json`, and generate the filter with the given signature.

The command prints out the multisig public key and whether it was able to successfully verify the signature included in the filter.

### Verify a Filter

As a convenience you can also verify the signature of a given filter:

```shell
$ xorf-generator filter verify
{
"address": "1SVRdbb7Xe1ijHYwGMVx55wnmRRzwhb3jRkw5fAGr3zoaiqAq9tcLKKH",
"verify": true
}
```

will verify the signature of the (impied) `filter.bin`

### Check Filter Membership

As a convenience you can check if a given public key is in a binary filter:

```shell
$ xorf-generator filter contains 1112C1wiK9JDiEiuw79S6skHgtSDiYcvkRSWqfmJj1ncuDUgoLc
{
  "address": "1112C1wiK9JDiEiuw79S6skHgtSDiYcvkRSWqfmJj1ncuDUgoLc",
  "in_filter": true
}
```
