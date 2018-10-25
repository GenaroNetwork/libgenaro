libgenaro  
=======
document: [usage](./usage.md)

[![Build Status](https://travis-ci.org/GenaroNetwork/libgenaro.svg?branch=master)](https://travis-ci.org/GenaroNetwork/libgenaro)

Asynchronous multi-platform C library and CLI for encrypted file transfer on the Genaro network.
Forked from libstorj with additional functions added.

For usage, see usage.md for examples, and see genaro.h for api.

## Feature Highlights

- Asynchronous I/O with concurrent peer-to-peer network requests for shards
- Erasure encoding with reed solomon for data durability
- Robust handling of shard transfers by selecting alternative sources
- File integrity and authenticity verified with HMAC-SHA512
- File encryption with AES-256-CTR
- File name and bucket name encryption with AES-256-GCM
- Proxy support with SOCKS5, SOCKS4, SOCKS4a
- Asynchronous progress updates in bytes per file
- Transfers can be cleanly canceled per file
- Seed based file encryption key for portability between devices

## Build

** OS X / Debian / Ubuntu **

```bash
mkdir build
cd build
cmake ..
make
```

** Windows **

```cmd
md build
cd build
cmake -G "MinGW Makefiles" ..
mingw32-make
```

To run tests:
```bash
./build/tests
```

To run command line utility:
```bash
./build/genaroeden-cli --help
```

### OS X Dependencies (w/ homebrew):

Development tools:
```bash
brew install libtool automake
git clone https://github.com/bitcoin-core/secp256k1.git /tmp/secp256k1
cd /tmp/secp256k1
./autogen.sh
./configure
make
sudo make install
git clone https://github.com/maandree/libkeccak.git /tmp/libkeccak
cd /tmp/libkeccak
```

Modify the contents of Makefile:
```Makefile
  # for Linux
  LIBEXT = so
  LIBFLAGS = -shared -Wl,-soname,libkeccak.$(LIBEXT).$(LIB_MAJOR)
  # for Mac OS
  # LIBEXT = dylib
  # LIBFLAGS = -dynamiclib
```
to：
```Makefile
  # for Linux
  # LIBEXT = so
  # LIBFLAGS = -shared -Wl,-soname,libkeccak.$(LIBEXT).$(LIB_MAJOR)
  # for Mac OS
  LIBEXT = dylib
  LIBFLAGS = -dynamiclib
```

and then:
```bash
make
sudo make install
```

Dependencies:
```bash
brew install gmp json-c libuv nettle libmicrohttpd libscrypt
```

### Debian / Ubuntu (16.04) Dependencies:

Development tools:
```bash
apt-get install build-essential libtool autotools-dev automake libmicrohttpd-dev bsdmainutils
```

Dependencies:
```bash
apt-get install libcurl4-gnutls-dev nettle-dev libjson-c-dev libuv1-dev libsecp256k1-dev libscrypt-dev
git clone https://github.com/maandree/libkeccak.git /tmp/libkeccak
cd /tmp/libkeccak
make
sudo make install
```

If libsecp256k1-dev(library secp256k1) can't be installed, try:
```bash
git clone https://github.com/bitcoin-core/secp256k1.git /tmp/secp256k1
cd /tmp/secp256k1
./autogen.sh
./configure
make
sudo make install
```

### Windows Dependencies:

TBD.
