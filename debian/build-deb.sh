#!/bin/bash

set -e

cargo build --release
mkdir -p usr/bin/
cp ../target/release/titun usr/bin/titun
trap "rm usr/bin/titun" 0
fpm -s dir -t deb -n titun -v 0.0.4 --license GPL-3.0 -d "libc6 (>= 2.19)" -d "libsodium18 (>= 1.0.8)" --vendor "sopium" --maintainer "sopium" --deb-priority optional --url https://github.com/sopium/titun --force -x '*.deb' -x build-deb.sh -x .gitignore .
