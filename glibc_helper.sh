# Helper functions for downloading and copying glibc libraries
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
