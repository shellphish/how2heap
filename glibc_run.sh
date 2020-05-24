#!/bin/bash

VERSION="./glibc_versions"
DIR_TCACHE='tcache'
DIR_HOST='x64'
OUTPUT_DIR="$VERSION/$1/${DIR_HOST}_${DIR_TCACHE}/lib"

if [[ $# < 2 ]]; then
    echo "Usage: $0 <version> <target>";
    exit 1
fi

# Get glibc source
if [ ! -e "$OUTPUT_DIR/libc-$1.so" ]; then
    echo "Error: Glibc-version wasn't build. Build it first:"
    echo "./build_glibc $1 <#make-threads"
fi

curr_interp=$(readelf -l "$2" | grep 'Requesting' | cut -d':' -f2 | tr -d ' ]')
target_interp="$OUTPUT_DIR/ld-$1.so"

if [[ $curr_interp != $target_interp ]];
then
    patchelf --set-interpreter "$target_interp" "$2"
fi

"$2"
