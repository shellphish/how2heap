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

LD_PRELOAD="$VERSION/libc-$1.so" "$VERSION/ld-$1.so" "$2"
