#!/bin/bash

VERSION="./glibc_versions"

if [[ $# < 2 ]]; then
    echo "Usage: $0 <version> <target>";
    exit 1
fi

# Get glibc source
if [ ! -e "$VERSION/libc-$1.so" ]; then
    echo "Error: Glibc-version wasn't build. Build it first:"
    echo "./build_glibc $1 <#make-threads"
fi

curr_interp=$(readelf -l "$2" | grep 'Requesting' | cut -d':' -f2 | tr -d ' ]')
target_interp="$VERSION/ld-$1.so"

if [[ $curr_interp != $target_interp ]];
then
    patchelf --set-interpreter "$target_interp" "$2"
fi

LD_PRELOAD="$VERSION/libc-$1.so" "$2"
