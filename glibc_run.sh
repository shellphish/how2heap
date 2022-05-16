#!/bin/bash

VERSION="./glibc_versions"
DIR_TCACHE='tcache'
DIR_HOST='x64'
GLIBC_VERSION=''
TARGET=''
USING_GDB=0

# Handle arguments
function show_help {
    echo "Usage: $0 <version> <target> [-h] [-disable-tcache] [-i686] [-gdb]"
}

if [[ $# < 2 ]]; then
    show_help
    exit 1
fi

GLIBC_VERSION=$1
TARGET=$2

while :; do
    case $3 in
        -h|-\?|--help)
            show_help
            exit
            ;;
        -disable-tcache)
            DIR_TCACHE='notcache'
            ;;
        -i686)
            DIR_HOST='i686'
            ;;
        -gdb)
            USING_GDB=1
            ;;
        '')
            break
            ;;
    esac
    shift
done

OUTPUT_DIR="$VERSION/$GLIBC_VERSION/${DIR_HOST}_${DIR_TCACHE}/lib"

# Get glibc source
if [ ! -e "$OUTPUT_DIR/libc-$GLIBC_VERSION.so" ]; then
    echo "Error: Glibc-version wasn't build. Build it first:"
    echo "./build_glibc $GLIBC_VERSION <#make-threads"
fi

curr_interp=$(readelf -l "$TARGET" | grep 'Requesting' | cut -d':' -f2 | tr -d ' ]')
target_interp="$OUTPUT_DIR/ld-$GLIBC_VERSION.so"

if [[ $curr_interp != $target_interp ]];
then
    patchelf --set-interpreter "$target_interp" "$TARGET"
fi

if [ $USING_GDB -eq 1 ]; then
  gdb "$TARGET"
else
  "$TARGET"
fi
