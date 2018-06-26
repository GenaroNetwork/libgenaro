cmake_minimum_required(VERSION 3.5.0)
project(libgenaro VERSION 0.1.0)

include(CTest)
enable_testing()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(../secp256k1 build-secp256k1)
add_subdirectory(../libscrypt build-libscrypt)
add_subdirectory(../libkeccak build-libkeccak)

include_directories(../secp256k1/include)
include_directories(../libscrypt)
include_directories(../libkeccak)

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

add_executable(cli src/cli.c)
target_link_libraries(cli genaro uv json-c nettle curl secp256k1 scrypt keccak)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
