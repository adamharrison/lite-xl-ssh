#!/usr/bin/env bash

: ${CC=gcc}
: ${HOSTCC=$CC}
: ${AR=ar}
: ${MAKE=make}
: ${BIN=libssh.so}
: ${JOBS=4}

[[ "$@" == "clean" ]] && rm -rf lib/prefix $BIN && exit 0

CFLAGS="$CFLAGS -fPIC -Ilib/prefix/include -Ilib/lite-xl/resources/include"
LDFLAGS="$LDFLAGS -Llib/prefix/lib -Llib/prefix/lib64 -Wl,-Bstatic -lssh2 -lcrypto -ldl -pthread -lz -Wl,-Bdynamic"

mkdir -p lib/prefix/include lib/prefix/lib

# We can only build with one job here, because the generated makefile is misconfigured.
[ ! -e "lib/prefix/lib64/libcrypto.a" ] && { cd lib/openssl && ./Configure --prefix=`pwd`/../prefix no-shared -fPIC no-hw no-engine no-dso no-srp && $MAKE install_sw -j 1 && cd ../.. || exit -1; }
[ ! -e "lib/prefix/lib/libssh2.a" ] && { cd lib/libssh2 && rm -rf build && mkdir build && cd build && cmake .. -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_INSTALL_PREFIX=`pwd`/../../prefix && make -j $JOBS && make install && cd ../../.. || exit -1; }

$CC $CFLAGS *.c $LDFLAGS -shared $@ -o $BIN

