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
DOCKER=''
GDB=''
RADARE2=''
NOT_EXECUTION=''
FORCE_TARGET_INTERPRETER=''
HOW2HEAP_PATH=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# Handle arguments
function show_help {
    echo "Usage: $0 <version> <target> [-h] [-i686] [-u] [-r] [-d] [-gdb | -r2 | -p]"
    echo "-i686 - use x32 bits libc"
    echo "-u - update libc list in glibc-all-in-one"
    echo "-r - download libc in glibc-all-in-one"
    echo "-d - build the debugging environment in docker"
    echo "-gdb - start target in GDB"
    echo "-r2 - start target in radare2"
    echo "-p - just set interpreter and rpath in target without execution"
}

if [[ $# < 2 ]]; then
    show_help
    exit 1
fi

function init_glibc(){
    git submodule update --init --recursive
}

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
    
    if [[ $curr_interp != $1 ]];
    then
        patchelf --set-interpreter "$1" "$TARGET"
        echo "INTERPERETER as $1 for $TARGET"
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

function prep_in_docker () {
	# choose the correct base ubuntu container
	if (( $(echo "$1 > 2.33" |bc -l) ));
	then
		UBUNTU_VERSION="22.04"
	else
		UBUNTU_VERSION="20.04"
	fi

	# make sure we have access to docker
	docker --version >/dev/null 2>&1
	if test $? -ne 0;
	then
		echo "please make sure docker is installed and you have access to it first"
		exit -1
	fi

	# build the docker image
	sed -i "1s/.*/from ubuntu:$UBUNTU_VERSION/" Dockerfile
	echo "building the how2heap_docker image!"
	docker build -t how2heap_docker .

	docker run --rm -it -u $(id -u ${USER}):$(id -g ${USER}) -v $HOW2HEAP_PATH:/root/how2heap how2heap_docker make clean all >/dev/null
}

GLIBC_VERSION=$1
GLIBC_MAJOR=$(echo $GLIBC_VERSION | cut -d'.' -f1)
GLIBC_MINOR=$(echo $GLIBC_VERSION | cut -d'.' -f2)
TARGET=$2
SYSTEM_GLIBC_VERSION=$(lsof -p $$ 2>/dev/null | grep libc- | awk ' { print $NF" --version"; } ' | sh | head -n 1 | cut -d' ' -f 10 | cut -d'.' -f 1-2)
SYSTEM_GLIBC_MAJOR=$(echo $SYSTEM_GLIBC_VERSION | cut -d'.' -f1)
SYSTEM_GLIBC_MINOR=$(echo $SYSTEM_GLIBC_VERSION | cut -d'.' -f2)
SYSTEM_GLIBC=$(lsof -p $$ 2>/dev/null | grep libc- | awk ' { print $NF" --version"; } ' | sh | head -n 1 | cut -d' ' -f 10)

if [ ! -f $TARGET ]; then
    echo "Create binaries by make"
    exit
fi

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
        -d)
            DOCKER='X'
        ;;
        -gdb)
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


if [ ! -d ./glibc-all-in-one/LICENSE ]; then
    init_glibc
fi

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

if [ -z "$libc" ]
then
    libc=$(cat glibc-all-in-one/old_list | grep "$GLIBC_VERSION" | grep "$LIB_HOST" | head -n 1)
fi

download_glibc $libc $RELOAD
copy_glibc $libc
if [ -z "$(ls -A $OUTPUT_DIR)" ]; then
    echo "Couldn't download and extract glibc."
    echo "Check you have installed zstd"
    exit
fi
target_interpreter="$OUTPUT_DIR/$(ls $OUTPUT_DIR | grep ld)"

if [ "$DOCKER" == 'X' ];
then
	prep_in_docker $GLIBC_VERSION
fi

if [[ $GLIBC_MAJOR != $SYSTEM_GLIBC_MAJOR ]] || [[ $GLIBC_MINOR != $SYSTEM_GLIBC_MINOR ]]; then
    set_interpreter $target_interpreter
    set_rpath
fi

if [ "$GDB" == 'X' ];
then
    if [[ $GLIBC_VERSION != $SYSTEM_GLIBC_VERSION ]]; then
        gdb $TARGET -iex "set debug-file-directory $OUTPUT_DIR/.debug"
    else
        gdb $TARGET
    fi
elif [ "$RADARE2" == 'X' ];
then
    r2 -d $TARGET
elif [ "$NOT_EXECUTION" == ''  ];
then
    "$TARGET"
else
    echo "$TARGET It's ready for discovering"
fi
