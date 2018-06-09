#!/bin/bash

SRC="./glibc_src"
BUILD="./glibc_build"
VERSION="./glibc_versions"

if [[ $# < 2 ]]; then
    echo "Usage: $0 <version> <#make-threads>"
    exit 1
fi

# Get glibc source
if [ -d "$SRC" ]; then
    cd $SRC
    git pull --all
else
    git clone git://sourceware.org/git/glibc.git "$SRC"
    cd "$SRC"
    git pull --all
fi

# Checkout release
git rev-parse --verify --quiet "release/$1/master"
if [[ $? != 0 ]]; then
    echo "Error: Glib version does not seem to exists"
    exit 1
fi

git checkout "release/$1/master"
cd -

# Build
mkdir -p "$BUILD"
cd "$BUILD" && rm -rf ./*
../"$SRC"/configure --prefix=/usr
make -j "$2"
cd -

# Copy to version folder
mkdir -p "$VERSION"
cp "$BUILD/libc.so" "$VERSION/libc-$1.so"
cp "$BUILD/elf/ld.so" "$VERSION/ld-$1.so"





