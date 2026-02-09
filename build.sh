#!/usr/bin/env bash

: ${CC=gcc}
: ${HOSTCC=$CC}
: ${AR=ar}
: ${MAKE=make}
: ${BIN=libssh.so}
: ${JOBS=4}

[[ "$@" == "clean" ]] && rm -rf lib/prefix lib/mbedtls/build lib/libssh2/build $BIN && exit 0

CFLAGS="$CFLAGS -fPIC -Ilib/prefix/include -Ilib/lite-xl/resources/include"
LDFLAGS="$LDFLAGS -Llib/prefix/lib -Llib/prefix/lib64"
CMAKE_DEFAULT_FLAGS="$CMAKE_DEFAULT_FLAGS -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER -DBUILD_SHARED_LIBS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=NEVER -DCMAKE_INSTALL_PREFIX=`pwd`/lib/prefix"

mkdir -p lib/prefix/include lib/prefix/lib

# We can only build with one job here, because the generated makefile is misconfigured.
if [[ "$@" != *"-lmbedcrypto"* ]]; then
  [ ! -e "lib/mbedtls/build" ] && { cd lib/mbedtls && mkdir build && cd build && CFLAGS="$CFLAGS -w" cmake .. $CMAKE_DEFAULT_FLAGS -G "Unix Makefiles" -DENABLE_TESTING=OFF -DENABLE_PROGRAMS=OFF && $MAKE -j $JOBS && CFLAGS="$CFLAGS -w" $MAKE install && cd ../../../ || exit -1; }
  LDFLAGS="$LDFLAGS -lmbedcrypto"
fi
if [[ "$@" != *"-lssh2"* ]]; then
  [ ! -e "lib/libssh2/build" ] && { cd lib/libssh2 && rm -rf build && mkdir build && cd build && cmake .. $CMAKE_DEFAULT_FLAGS -DCRYPTO_BACKEND="mbedTLS" -G "Unix Makefiles" && make -j $JOBS && make install && cd ../../.. || exit -1; }
  LDFLAGS="-lssh2 $LDFLAGS"
fi
[[ "$CC" == *"mingw"* ]] && LDFLAGS="$LDFLAGS -lws2_32 -lbcrypt"

$CC $CFLAGS *.c $LDFLAGS -shared $@ -o $BIN

