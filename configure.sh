./configure PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/:$PWD/../openssl/build/lib/pkgconfig LDFLAGS="-Wl,-rpath,$PWD/../openssl/build/lib -llexbor" LIBS="-lhiredis" --host=arm
