#!/bin/bash

# Script to download all glibc libraries
# Import helper functions
source ./glibc_helper.sh

VERSION="./glibc_versions"
LIB_HOST='amd64'
DIR_HOST='x64'
# Array of all glibc versions
ALL_GLIBC_VERSIONS=("2.23" "2.24" "2.27" "2.31" "2.32" "2.33" "2.34" "2.35" "2.36" "2.37" "2.38" "2.39")

if [ ! -d ./glibc-all-in-one/LICENSE ]; then
    init_glibc
fi

update_glibc "X"

for GLIBC_VERSION in "${ALL_GLIBC_VERSIONS[@]}"
do
    OUTPUT_DIR="$VERSION/$GLIBC_VERSION/${DIR_HOST}/lib"
    if [ ! -d "$OUTPUT_DIR" ];
    then
        mkdir -p $OUTPUT_DIR
    fi
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
done


