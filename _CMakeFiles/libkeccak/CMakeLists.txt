cmake_minimum_required(VERSION 3.5)
project(libkeccak LANGUAGES C)

aux_source_directory(libkeccak SRC)
add_library(keccak ${SRC})
