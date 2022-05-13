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
FORCE_TARGET_INTERPRETER=''

# Handle arguments
function show_help {
    #echo "Usage: $0 <version> <target> [-h] [-disable-tcahe] [-i686] [-u] [-r] [-g [-r2] [-p]"
    echo "Usage: $0 <version> <target> [-h] [-i686] [-u] [-r] [-g [-r2] [-p] [-si] [-ti]"
    echo "-i686 - use x32 bits libc"
    echo "-u - update libc list in glibc-sll-in-one"
    echo "-r - download libc in glibc-all-in-one"
    echo "-g - start target in GDB"
    echo "-r2 - start target in radare2"
    echo "-p - just set interpreter and rpath in target without execution"
    #echo "-si - set system interpreter"
    echo "-ti - force to set target interpreter"
}

if [[ $# < 2 ]]; then
    show_help
    exit 1
fi

function update_glibc (){
    if [ "$1" == "X" ] || [ ! -f glibc-all-in-one/list ]; then
        cd glibc-all-in-one
        ./update_list
        cd -
    fi
}

function download_glibc (){
    if [ "$2" == "X" ] || [ ! -d glibc-all-in-one/libs/$libc ]; then
        cd glibc-all-in-one
        rm -rf libs/$1 debs/$1
        ./download $1
        ./download_old $1
        cd -
    fi
}

function copy_glibc (){
    if [ ! -f "$OUTPUT_DIR/libc-$GLIBC_VERSION.so" ]; then
        cp -r glibc-all-in-one/libs/$1/* $OUTPUT_DIR
        cp -r glibc-all-in-one/libs/$1/.debug $OUTPUT_DIR
    fi
}

function set_interpreter (){
    
    local curr_interp=$(patchelf --print-interpreter "$TARGET")
    #local target_interp="$OUTPUT_DIR/ld-$GLIBC_VERSION.so"
    #local target_interp=$(ls glibc_versions/2.34/x64/lib | grep ld)
    
    if [[ $curr_interp != $1 ]];
    then
        patchelf --set-interpreter "$1" "$TARGET"
        echo "INERPERETER as $1 for $TARGET"
    fi
}

function set_rpath (){
    curr_rpath=$(patchelf --print-rpath "$TARGET")
    
    if [[ $curr_rpath != $OUTPUT_DIR ]];
    then
        patchelf --set-rpath "$OUTPUT_DIR" "$TARGET"
        echo "RPATH as $OUTPUT_DIR"
    fi
}

GLIBC_VERSION=$1
GLIBC_MAJOR=$(echo $GLIBC_VERSION | cut -d'.' -f1)
GLIBC_MINOR=$(echo $GLIBC_VERSION | cut -d'.' -f2)
TARGET=$2
SYSTEM_GLIBC_VERSION=$(lsof -p $$ 2>/dev/null | grep libc- | awk ' { print $NF" --version"; } ' | sh | head -n 1 | cut -d' ' -f 10 | cut -d'.' -f 1-2)
SYSTEM_GLIBC_MAJOR=$(echo $SYSTEM_GLIBC_VERSION | cut -d'.' -f1)
SYSTEM_GLIBC_MINOR=$(echo $SYSTEM_GLIBC_VERSION | cut -d'.' -f2)
SYSTEM_GLIBC=$(lsof -p $$ 2>/dev/null | grep libc- | awk ' { print $NF" --version"; } ' | sh | head -n 1 | cut -d' ' -f 10)

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
        -ti)
	    FORCE_TARGET_INTERPRETER='X'
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

update_glibc $UPDATE
libc=$(cat glibc-all-in-one/list | grep "$GLIBC_VERSION" | grep "$LIB_HOST" | head -n 1)
download_glibc $libc $RELOAD
copy_glibc $libc
if [ -z "$(ls -A $OUTPUT_DIR)" ]; then
    echo "Couldn't download and extract glibc."
    echo "Check you have installed zstd"
    exit
fi
target_interpreter="$OUTPUT_DIR/$(ls $OUTPUT_DIR | grep ld)"

if [[ "$GLIBC_MAJOR" < "$SYSTEM_GLIBC_MAJOR" ]];
then
    set_interpreter $target_interpreter
    set_rpath
else
    if [[ "$GLIBC_MINOR" < "$SYSTEM_GLIBC_MINOR" ]];
    then
        set_interpreter $target_interpreter
        set_rpath
    else
	if [ ! -z $FORCE_TARGET_INTERPRETER ]; then
            set_interpreter $target_interpreter
	fi
        set_rpath
    fi
fi

if [ "$GDB" == 'X' ];
then
   gdb $TARGET -iex "set debug-file-directory $OUTPUT_DIR/.debug"
elif [ "$RADARE2" == 'X' ];
then
    r2 -d $TARGET
elif [ "$NOT_EXECUTION" == ''  ];
then
    "$TARGET"
else
    echo "$TARGET It's ready for discovering"
fi
