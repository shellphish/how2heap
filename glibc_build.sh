#!/bin/bash

SRC="./glibc_src"
BUILD="./glibc_build"
VERSION="./glibc_versions"

CC='gcc'
CXX='g++'

# Handle arguments
function show_help {
    echo "Usage: $0 version [-h|--help] [-j make_threads] [-disable-tcache] [-i686]"
}

if [[ $# < 1 ]]; then
    show_help
    exit 1
fi

DIR_TCACHE='tcache'
DIR_HOST='x64'
BUILD_OPTS=''
GLIBC_VERSION=''

while :; do
    case $1 in
        -h|-\?|--help)
            show_help
            exit
            ;;
        -j)
            if [ "$2" ]; then
                make_threads="$2"
                if [[ ! $make_threads =~ ^[0-9]+$ ]]; then
                    echo 'Error: "-j" option must be integer'
                    exit 1
                fi
                echo "  -> Using $make_threads threads"
                shift
            else
                echo 'Error: "-j" requires a non-empty option argument.'
                exit 1
            fi
            ;;
        -disable-tcache)
            echo '  -> Disabling tcache'
            DIR_TCACHE='notcache'
            BUILD_OPTS="$BUILD_OPTS --disable-experimental-malloc"
            ;;
        -i686)
            echo '  -> Building for i686'
            DIR_HOST='i686'
            BUILD_OPTS="$BUILD_OPTS CC='$CC -m32' CXX='$CXX -m32'"
            BUILD_OPTS="$BUILD_OPTS --host=i686-linux-gnu --build=i686-pc-linux-gnu"
            BUILD_OPTS="$BUILD_OPTS CFLAGS='-O2 -m32' CXXFLAGS='-O2 -m32' LDFLAGS='-m32'"
            ;;
        '')
            break
            ;;
        *)
            if [ ! -z $GLIBC_VERSION ]; then
                echo "Error: Unknow option $1"
                exit 1
            fi
            GLIBC_VERSION="$1"
            ;;
    esac

    shift
done

if [ -z $GLIBC_VERSION ]; then
    echo 'Error: First argument must be glibc version'
    show_help
    exit 1
fi

# Prepare output dir
OUTPUT_DIR="$VERSION/$GLIBC_VERSION/${DIR_HOST}_${DIR_TCACHE}"

# Get glibc source
if [ ! -d "$SRC" ]; then
    git clone git://sourceware.org/git/glibc.git "$SRC"
fi
cd "$SRC"
git pull --all

# Checkout release
git rev-parse --verify --quiet "refs/remotes/origin/release/$GLIBC_VERSION/master"
if [[ $? != 0 ]]; then
    echo "Error: Glibc version \"$GLIBC_VERSION\" does not seem to exists"
    exit 1
fi

git checkout "release/$GLIBC_VERSION/master" -f
git pull
cd -

# Prepare build directory
mkdir -p "$BUILD"
cd "$BUILD"
if grep -q "$OUTPUT_DIR" ./how2heap_build_cmd; then
    echo "  -> Not clearing build directory"
else
    echo "  -> Clearing build directory"
    rm -rf ./*
fi
eval ../"$SRC"/configure --prefix=/usr $BUILD_OPTS
echo "$OUTPUT_DIR" > ./how2heap_build_cmd
make -j "$make_threads"
cd -

# Save compiled
if [ "$(ls -A $OUTPUT_DIR 2>/dev/null)" ]; then
    echo "  -> Directory \"$OUTPUT_DIR\" exists and is not empty, skipping copy step"
    exit
fi
mkdir -p "$OUTPUT_DIR"

echo "  -> Copying libraries to $OUTPUT_DIR"
cd "$BUILD"
find . \( -name '*.so' -or -name '*.a' \) -exec rsync -aR "{}" "../$OUTPUT_DIR" \;
cd -
