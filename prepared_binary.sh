#!/bin/bash

VERSION="./glibc_versions"
#DIR_TCACHE='tcache'
DIR_TCACHE=''
DIR_HOST='x64'
LIB_HOST='amd64'
GLIBC_VERSION=''
TARGET=''
UPDATE=''
RELOAD=''
GDB=''
RADARE2=''
NOT_EXECUTION=''

# Handle arguments
function show_help {
    #echo "Usage: $0 <version> <target> [-h] [-disable-tcahe] [-i686] [-u] [-r] [-g [-r2] [-p]"
    echo "Usage: $0 <version> <target> [-h] [-i686] [-u] [-r] [-g [-r2] [-p]"
    echo "-i686 - use x32 bits libc"
    echo "-u - update libc list in glibc-sll-in-one"
    echo "-r - download libc in glibc-all-in-one"
    echo "-g - start target in GDB"
    echo "-r2 - start target in radare2"
    echo "-p - just set interpreter and rpath in target without execution"
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
#        -disable-tcache)
#            DIR_TCACHE='notcache'
#            ;;
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
	-g)
	    GDB='X'
	    ;;
	-r2)
	    RADARE2='X'
	    ;;
	-p)
	   NOT_EXECUTION='X'
	   ;;
        '')
            break
            ;;
    esac
    shift
done

if [ -z $DIR_TCACHE ]; then
    OUTPUT_DIR="$VERSION/$GLIBC_VERSION/${DIR_HOST}/lib"
else
    OUTPUT_DIR="$VERSION/$GLIBC_VERSION/${DIR_HOST}_${DIR_TCACHE}/lib"
fi

if [ ! -d "$OUTPUT_DIR" ];
then
    mkdir -p $OUTPUT_DIR
fi

if [ "$UPDATE" == "X" ] || [ ! -f glibc-all-in-one/list ]; then
    cd glibc-all-in-one
    ./update_list
    cd -
fi

libc=$(cat glibc-all-in-one/list | grep "$GLIBC_VERSION" | grep "$LIB_HOST" | head -n 1)

if [ "$RELOAD" == "X" ] || [ ! -d glibc-all-in-one/libs/$libc ]; then
    cd glibc-all-in-one
    ./update_list
    rm -rf libs/$libc debs/$libc
    ./download $libc
    cd -
fi

if [ ! -f "$OUTPUT_DIR/libc-$GLIBC_VERSION.so" ]; then
    cp -r glibc-all-in-one/libs/$libc/. $OUTPUT_DIR
fi

curr_interp=$(patchelf --print-interpreter "$TARGET")
target_interp="$OUTPUT_DIR/ld-$GLIBC_VERSION.so"

if [[ $curr_interp != $target_interp ]];
then
    patchelf --set-interpreter "$target_interp" "$TARGET"
    echo "INERPERETER as $target_interp for $TARGET"
fi

curr_rpath=$(patchelf --print-rpath "$TARGET")

if [[ $curr_rpath != $OUTPUT_DIR ]];
then
    patchelf --set-rpath "$OUTPUT_DIR" "$TARGET"
    echo "RPATH as $OUTPUT_DIR"
fi

if [ "$GDB" == 'X' ]; then
    gdb $TARGET --symbols $OUTPUT_DIR --se $TARGET
elif [ "$RADARE2" == 'X' ]; then
    r2 -d $TARGET
elif [ "$NOT_EXECUTION" == ''  ]; then
    "$TARGET"
else
    echo "$TARGET It's ready for discovering"
fi
