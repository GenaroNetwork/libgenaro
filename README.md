# libgenaro  

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
- The key of AES-256-CTR can be provided to decrypt the encrypted file, so that file sharing can be easily implemented
- String can be encrypted with AES-256-CTR and directly stored to a bucket

## Build

**OS X / Debian / Ubuntu**

```bash
mkdir build
cd build
cmake ..
make
```

**Windows**

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

and then install dependencies:

```bash
brew install gmp json-c libuv nettle libmicrohttpd libscrypt
```

### Debian / Ubuntu (16.04) Dependencies

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

### Windows Dependencies

1. Cross Compiling Dependencies from Ubuntu 16.04:

a):

```bash
apt-get install gcc-mingw-w64-x86-64 gcc-mingw-w64-i686 g++-mingw-w64-i686 g++-mingw-w64-x86-64 m4 autoconf automake libtool pkg-config curl
```

b):

```bash
cd depends
make HOST="x86_64-w64-mingw32"
```

Command "make HOST="x86_64-w64-mingw32" will start to download the source code packages, when all the packages is downloaded and extracted(when appearing "checking ..."), break this command, and do these:
  aa) open "depends/sources/x86_64-w64-mingw32/json-c/configure.ac", add " -Wno-error=implicit-fallthrough" after "-Wno-error=deprecated-declarations";
  bb) open "depends/sources/x86_64-w64-mingw32/libkeccak/Makefile", delete the whole contents, and input:

```Makefile
CC = x86_64-w64-mingw32-gcc
OBJS = libkeccak/state.o libkeccak/digest.o
LIBKECCAK = libkeccak.a
DES_DIR = ../../../build/x86_64-w64-mingw32/lib
$(LIBKECCAK): $(OBJS)
	x86_64-w64-mingw32-ar rcs $(LIBKECCAK) $(OBJS)
install:
	mkdir -p $(DES_DIR) && cp -f $(LIBKECCAK) $(DES_DIR)
clean:
	rm -f $(OBJS) $(LIBKECCAK)
```

and run "make clean" in the directory "depends/sources/x86_64-w64-mingw32/libkeccak".

  cc) open "depends/sources/x86_64-w64-mingw32/libscrypt/Makefile", delete the whole contents, and input:

```Makefile
CC = x86_64-w64-mingw32-gcc
OBJS = crypto_scrypt-nosse.o sha256.o crypto-mcf.o b64.o crypto-scrypt-saltgen.o crypto_scrypt-check.o crypto_scrypt-hash.o slowequals.o
LIBSCRYPT = libscrypt.a
DES_DIR = ../../../build/x86_64-w64-mingw32/lib
$(LIBSCRYPT): $(OBJS)
	x86_64-w64-mingw32-ar rcs $(LIBSCRYPT) $(OBJS)
install:
	mkdir -p $(DES_DIR) && cp -f $(LIBSCRYPT) $(DES_DIR)
clean:
	rm -f $(OBJS) $(LIBSCRYPT)
```

and run "make clean" in the directory "depends/sources/x86_64-w64-mingw32/libscrypt".

c):
run:

```bash
make HOST="x86_64-w64-mingw32"
```

again.

2. Install Dependencies on Windows:

Install MinGW-w64 and add the "bin" directory to environment "PATH".
Install CMake.
