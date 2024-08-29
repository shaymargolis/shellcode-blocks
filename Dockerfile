FROM ubuntu:22.04

RUN apt-get update && apt-get install -y python3 python3-pip python-is-python3
RUN apt-get update && apt-get install -y gcc-9-mips-linux-gnu binutils-multiarch
