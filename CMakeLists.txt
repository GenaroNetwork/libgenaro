cmake_minimum_required(VERSION 3.5.0)
project(libgenaro VERSION 0.1.0)

SET(DEBUG 1)
SET(STATIC 1)
SET(COVERAGE 0)

IF(APPLE)

set(CMAKE_OSX_DEPLOYMENT_TARGET "10.13")

IF(DEBUG)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -gdwarf-2 -g3")
ENDIF()

IF(COVERAGE)
# SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -coverage")
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -fprofile-arcs -ftest-coverage")
ENDIF()

# include(CTest)
# enable_testing()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(/usr/local/include)
link_directories(/usr/local/lib)

# get the path of the Developer dir of Xcode
execute_process(COMMAND xcode-select --print-path OUTPUT_VARIABLE Xcode-dev-dir)
# strip the last newline character
string(STRIP ${Xcode-dev-dir} Xcode-dev-dir)
include_directories(${Xcode-dev-dir}/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include)

add_library(genaro
        src/genaro.c
        src/bip39.c
        src/crypto.c
        src/downloader.c
        src/http.c
        src/key_file.c
        src/rs.c
        src/uploader.c
        src/utils.c)
IF(STATIC)
  target_link_libraries(genaro /usr/local/lib/libsecp256k1.a /usr/local/lib/libscrypt.a /usr/local/lib/libkeccak.a /usr/local/lib/libgmp.a)
ELSE()
  target_link_libraries(genaro secp256k1 scrypt keccak gmp)
ENDIF()

add_executable(genaroeden-cli src/cli.c)
IF(STATIC)
  target_link_libraries(genaroeden-cli genaro /usr/local/lib/libuv.a /usr/local/lib/libjson-c.a /usr/local/lib/libnettle.a libcurl.a libsecp256k1.a /usr/local/lib/libscrypt.a libkeccak.a /usr/local/lib/libgmp.a)
ELSE()
  target_link_libraries(genaroeden-cli genaro uv json-c nettle curl secp256k1 scrypt keccak)
ENDIF()

add_executable(tests_rs test/tests_rs.c)

add_executable(tests test/mockbridge.c test/mockfarmer.c test/tests.c)
IF(STATIC)
  target_link_libraries(tests genaro /usr/local/lib/libuv.a /usr/local/lib/libjson-c.a /usr/local/lib/libnettle.a libcurl.a /usr/local/lib/libmicrohttpd.a)
ELSE()
  target_link_libraries(tests genaro uv json-c nettle curl microhttpd)
ENDIF()

add_executable(test_crypto test/test_crypto.c)
IF(STATIC)
  target_link_libraries(test_crypto genaro /usr/local/lib/libnettle.a)
ELSE()
  target_link_libraries(test_crypto genaro nettle)
ENDIF()

# set(CPACK_PROJECT_NAME ${PROJECT_NAME})
# set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
# include(CPack)

ELSEIF(UNIX)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -DCURL_STATICLIB -pthread")

IF(DEBUG)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g3")
ENDIF()

IF(COVERAGE)
# SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -coverage")
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -fprofile-arcs -ftest-coverage")
ENDIF()

include_directories(depends/build/x86_64-pc-linux-gnu/include)
link_directories(depends/build/x86_64-pc-linux-gnu/lib)

add_library(genaro
        src/genaro.c
        src/bip39.c
        src/crypto.c
        src/downloader.c
        src/http.c
        src/key_file.c
        src/rs.c
        src/uploader.c
        src/utils.c)

target_link_libraries(genaro m z idn2 libnettle.a libhogweed.a libgmp.a libsecp256k1.a libscrypt.a libkeccak.a)

add_executable(genaroeden-cli src/cli.c)
target_link_libraries(genaroeden-cli genaro libcurl.a libuv.a libjson-c.a libgnutls.a libgmp.a)

add_executable(tests_rs test/tests_rs.c)

add_executable(tests test/mockbridge.c test/mockfarmer.c test/tests.c)
target_link_libraries(tests genaro gcrypt libcurl.a libuv.a libjson-c.a libgnutls.a libgmp.a libmicrohttpd.a)

add_executable(test_crypto test/test_crypto.c)
target_link_libraries(test_crypto genaro)

ELSEIF(WIN32)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCURL_STATICLIB -std=c99")

IF(DEBUG)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
ENDIF()

include_directories("C:/Program Files/Mingw-w64/opt/include")
include_directories(depends/build/x86_64-w64-mingw32/include)
include_directories(depends/sources/x86_64-w64-mingw32/libscrypt)
include_directories(depends/sources/x86_64-w64-mingw32/libkeccak)
link_directories(depends/build/x86_64-w64-mingw32/lib)
link_directories("C:/Program Files/Mingw-w64/opt/lib")

add_library(genaro
        src/genaro.c
        src/bip39.c
        src/crypto.c
        src/downloader.c
        src/http.c
        src/key_file.c
        src/rs.c
        src/uploader.c
        src/utils.c)
target_link_libraries(genaro secp256k1 scrypt keccak)

add_executable(genaroeden-cli src/cli.c)

# nettle must locate behind curl and gnutls，gmp must locate behind gnutls，hogweed must locate behind gnutls.
target_link_libraries(genaroeden-cli genaro uv json-c curl gnutls nettle hogweed gmp secp256k1 scrypt keccak ws2_32.lib Kernel32.lib Userenv.lib Psapi.lib Iphlpapi.lib Crypt32.lib)

add_executable(tests test/mockbridge.c test/mockfarmer.c test/tests.c)
target_link_libraries(tests genaro uv json-c curl gnutls nettle hogweed gmp microhttpd ws2_32.lib Kernel32.lib Userenv.lib Psapi.lib Iphlpapi.lib Crypt32.lib)

add_executable(test_crypto test/test_crypto.c)
target_link_libraries(test_crypto genaro nettle)

IF(DEBUG)
  set(CMAKE_C_FLAGS "-DCURL_STATICLIB -std=gnu99 -g")
ELSE()
  set(CMAKE_C_FLAGS "-DCURL_STATICLIB -std=gnu99")
ENDIF()

add_executable(tests_rs test/tests_rs.c)

ENDIF()
