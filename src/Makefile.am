lib_LTLIBRARIES = libgenaro.la
libgenaro_la_SOURCES = genaro.c utils.c utils.h http.c http.h uploader.c uploader.h downloader.c downloader.h bip39.c bip39.h bip39_english.h crypto.c crypto.h rs.c rs.h key_file.c key_file.h
libgenaro_la_LIBADD = -lcurl -lnettle -ljson-c -luv -lm -lscrypt -lkeccak -lsecp256k1
# The rules of thumb, when dealing with these values are:
# - Always increase the revision value.
# - Increase the current value whenever an interface has been added, removed or changed.
# - Increase the age value only if the changes made to the ABI are backward compatible.
# https://autotools.io/libtool/version.html
# The order for version-info is <current>:<revision>:<age>
libgenaro_la_LDFLAGS = -Wall -version-info 1:1:0
if BUILD_GENARO_DLL
libgenaro_la_LDFLAGS += -no-undefined
endif
include_HEADERS = genaro.h

bin_PROGRAMS = genaro
genaro_SOURCES = cli.c genaro.h
genaro_LDADD = libgenaro.la
if BUILD_GENARO_DLL
genaro_LDFLAGS = -Wall
else
genaro_LDFLAGS = -Wall -static
endif
