# Ubuntu 20.04 is used due to Issue #169
ARG image=mcr.microsoft.com/devcontainers/base:focal 
FROM $image

# Build dependencies
run apt-get update && apt-get install -y binutils git make vim gcc patchelf python-is-python3 python3-pip

# Build how2heap
run git clone --depth 1 https://github.com/shellphish/how2heap /root/how2heap
run cd /root/how2heap && make clean all

# pwndbg
ENV LC_CTYPE=C.UTF-8 
run git clone --depth 1 https://github.com/pwndbg/pwndbg /root/pwndbg 
run git config --global --add safe.directory "*"
run cd /root/pwndbg && ./setup.sh 

# pwntools
run pip3 install requests pwntools


workdir /root/how2heap