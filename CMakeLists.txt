cmake_minimum_required(VERSION 3.0.0)
project(libgenaro VERSION 0.1.0)

include(CTest)
enable_testing()

add_subdirectory(../secp256k1 build-secp256k1)
add_subdirectory(../libscrypt build-libscrypt)

include_directories(../secp256k1/include)
include_directories(../libscrypt)
aux_source_directory(src SRC)

add_library(genaro src/genaro.c)

add_executable(cli ${SRC})
target_link_libraries(cli genaro uv json-c nettle curl secp256k1 scrypt)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
