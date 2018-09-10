cmake_minimum_required(VERSION 3.5.0)
project(libgenaro VERSION 0.1.0)

IF(APPLE)

set(CMAKE_OSX_DEPLOYMENT_TARGET "10.9")
# set(CMAKE_C_FLAGS "-gdwarf-2 -g3")

add_subdirectory(../secp256k1 build-secp256k1)
add_subdirectory(../libkeccak build-libkeccak)

include_directories(../secp256k1/include)
include_directories(../libkeccak)

include(CTest)
enable_testing()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_library(genaro
        src/genaro.c
        src/bip39.c
        src/crypto.c
        src/downloader.c
        src/http.c
        src/key_file.c
        src/rs.c
        src/uploader.c
        src/utils.c
        src/rsa.c)
target_link_libraries(genaro libsecp256k1.a libscrypt.a libkeccak.a)

add_executable(genaroeden-cli src/cli.c)
# target_link_libraries(genaroeden-cli genaro uv json-c nettle curl secp256k1 scrypt keccak)
target_link_libraries(genaroeden-cli genaro /usr/local/lib/libuv.a /usr/local/lib/libjson-c.a /usr/local/lib/libnettle.a libcurl.a libsecp256k1.a libscrypt.a libkeccak.a /usr/local/lib/libgmp.a)

# add_executable(tests_rs test/tests_rs.c)

# add_executable(tests test/mockbridge.c test/mockfarmer.c test/tests.c)
# target_link_libraries(tests genaro uv json-c nettle curl microhttpd)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

ELSEIF(UNIX)

set(CMAKE_C_FLAGS "-pthread")
# set(CMAKE_C_FLAGS "-g3")

add_library(genaro
        src/genaro.c
        src/bip39.c
        src/crypto.c
        src/downloader.c
        src/http.c
        src/key_file.c
        src/rs.c
        src/uploader.c
        src/utils.c
        src/rsa.c)
target_link_libraries(genaro libsecp256k1.a libscrypt.a libkeccak.a)

add_executable(genaroeden-cli src/cli.c)
# target_link_libraries(genaroeden-cli genaro m uv json-c nettle curl secp256k1 scrypt keccak)
target_link_libraries(genaroeden-cli genaro m libuv.a libjson-c.a libnettle.a curl libsecp256k1.a libscrypt.a libkeccak.a libgmp.a)

# add_executable(tests_rs test/tests_rs.c)

# add_executable(tests test/mockbridge.c test/mockfarmer.c test/tests.c)
# target_link_libraries(tests genaro uv json-c nettle curl microhttpd)

ELSEIF(WIN32)

# set(CMAKE_C_FLAGS "-DCURL_STATICLIB -Wall -std=c99 -g")
set(CMAKE_C_FLAGS "-DCURL_STATICLIB -Wall -std=c99")

include_directories(depends/build/x86_64-w64-mingw32/include)
include_directories(depends/sources/x86_64-w64-mingw32/libscrypt)
include_directories(depends/sources/x86_64-w64-mingw32/libkeccak)
link_directories(depends/build/x86_64-w64-mingw32/lib)

add_library(genaro
        src/genaro.c
        src/bip39.c
        src/crypto.c
        src/downloader.c
        src/http.c
        src/key_file.c
        src/rs.c
        src/uploader.c
        src/utils.c
        src/rsa.c)
target_link_libraries(genaro secp256k1 scrypt keccak)

add_executable(genaroeden-cli src/cli.c)

# nettle must locate behind curl and gnutls，gmp must locate behind gnutls，hogweed must locate behind gnutls.
target_link_libraries(genaroeden-cli genaro uv json-c curl gnutls nettle hogweed gmp secp256k1 scrypt keccak ws2_32.lib Kernel32.lib Userenv.lib Psapi.lib Iphlpapi.lib Crypt32.lib)

# add_executable(tests test/mockbridge.c test/mockfarmer.c test/tests.c)
# target_link_libraries(tests genaro uv json-c curl gnutls nettle hogweed gmp microhttpd ws2_32.lib Kernel32.lib Userenv.lib Psapi.lib Iphlpapi.lib Crypt32.lib)

ENDIF()
