#!/bin/bash

VERSION="./glibc_versions"
DIR_TCACHE='tcache'
DIR_HOST='x64'
LIB_HOST='amd64'
GLIBC_VERSION=''
TARGET=''
UPDATE=''
RELOAD=''

# Handle arguments
function show_help {
    echo "Usage: $0 <version> <target> [-h] [-disable-tcache] [-i686]"
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
	    LIB_HOST='i386'
            ;;
	-u)
	    UPDATE='X'
	    ;;
	-r)
	    RELOAD='X'
	    ;;
        '')
            break
            ;;
    esac
    shift
done

OUTPUT_DIR="$VERSION/$GLIBC_VERSION/${DIR_HOST}_${DIR_TCACHE}/lib"
libc=$(cat glibc-all-in-one/list | grep "$GLIBC_VERSION" | grep "$LIB_HOST" | tail -n 1)
if [ ! -d "$OUTPUT_DIR" ];
then
    mkdir -p $OUTPUT_DIR
fi
if [ ! -f "$OUTPUT_DIR/libc-$GLIBC_VERSION.so" ]; then
    if [ "$UPDATE" == "X" ] || [ "$RELOAD" == "X" ];
    then
        cd glibc-all-in-one
        if [ "$UPDATE" == "X" ] || [ ! -f ./list ]; then
            ./update_list
        fi

        if [ "$RELOAD" == "X" ] || [ ! -d libs/$libc ]; then
            ./update_list
            rm -rf libs/$libc debs/$libc
            ./download $libc
        fi
        cd -
    fi
    cp -r glibc-all-in-one/libs/$libc/* $OUTPUT_DIR
fi

curr_interp=$(patchelf --print-interpreter "$TARGET")
target_interp="$OUTPUT_DIR/ld-$GLIBC_VERSION.so"

if [[ $curr_interp != $target_interp ]];
then
    patchelf --set-interpreter "$target_interp" "$TARGET"
fi

curr_rpath=$(patchelf --print-rpath "$TARGET")

if [[ $curr_rpath != $OUTPUT_DIR ]];
then
    patchelf --set-rpath "$OUTPUT_DIR" "$TARGET"
fi
"$TARGET"
