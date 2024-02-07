# this is the dockerfile we use for testing techniques used in how2heap
from ubuntu:24.04

run apt-get update && apt-get -y install binutils git make vim gcc
run git clone --depth 1 https://github.com/shellphish/how2heap /root/how2heap

workdir /root/how2heap
run make
