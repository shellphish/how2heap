from ubuntu:20.04

run apt-get update && apt-get install -y binutils git make vim gcc patchelf python-is-python3 python3-pip
run pip3 install requests
run git clone --depth 1 https://github.com/shellphish/how2heap /root/how2heap
run git config --global --add safe.directory "*"

workdir /root/how2heap
run bash
