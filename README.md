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

1. Build the application using `cargo build --release` or download one of the
   [release packages](https://github.com/helium/xorf-generator/releases)

2. To create a signing key

   ```shell
   $ xorf-generator keypair create signing.key
   {
     "address": "142Q94DY68iJ95PzE56peh7PKtGJNfc6WM537tgtyfi3Z4o3kzX"
   }
   ```

   where `signing.key` is the output filename of your choosing. The result will
   include the b58 string of the public key for that keypair

   To get info for a given signing key:

   ```shell
   $ xorf-generator keypair info signing.key
   {
     "address": "142Q94DY68iJ95PzE56peh7PKtGJNfc6WM537tgtyfi3Z4o3kzX"
   }
   ```

3. To generate a filter from a csv file of public keys

   ```shell
   $ xorf-generator filter generate -i /hotspots.csv -o filter.bin --serial 1 --sign signing.key
   ```

   where the `hotspots.csv` is the list of public keys to include in the filter,
   `filter.bin` is the output file where the resulting signed binary should go,
   serial `1` is the serial number of the filter included to allow for ordering
   of filters, and `signing.key` is the file with a previously generated keypair
   to use for signing.

   To verify the signature of a given filter:

   ```shell
   $ xorf-generator filter verify -i filter.bin --key 142Q94DY68iJ95PzE56peh7PKtGJNfc6WM537tgtyfi3Z4o3kzX
   {
     "address": "142Q94DY68iJ95PzE56peh7PKtGJNfc6WM537tgtyfi3Z4o3kzX",
     "verify": true
   }
   ```

   and to check if a given public key is in a filter:

   ```shell
   $ xorf-generator filter contains -i filter.bin --key 1112C1wiK9JDiEiuw79S6skHgtSDiYcvkRSWqfmJj1ncuDUgoLc
   {
     "address": "1112C1wiK9JDiEiuw79S6skHgtSDiYcvkRSWqfmJj1ncuDUgoLc",
     "in_filter": true
   }
   ```
