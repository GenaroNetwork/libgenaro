cmake_minimum_required(VERSION 3.5)
project(libscrypt LANGUAGES C)

add_library(
        scrypt
        crypto_scrypt-nosse.c
        sha256.c
        crypto-mcf.c
        b64.c
        crypto-scrypt-saltgen.c
        crypto_scrypt-check.c
        crypto_scrypt-hash.c
        slowequals.c
)