FROM ubuntu:22.04

RUN apt update && apt install --no-install-recommends -y wget git automake libtool make cmake gcc g++ pkg-config libmagic-dev \
    tar unzip libglib2.0-0 libssl-dev libfuzzy-dev python3.9 python3.9-dev python3.9-pip

RUN apt install ssdeep

RUN wget --no-check-certificate https://github.com/protocolbuffers/protobuf/releases/download/v2.5.0/protobuf-2.5.0.tar.gz && \
    tar -xzf protobuf-2.5.0.tar.gz && rm protobuf-2.5.0.tar.gz && \
    cd protobuf-2.5.0 && ./configure && make && make install && ldconfig && cd .. && rm -rf protobuf-2.5.0/ 

# sdhash
ARG GIT_SSL_NO_VERIFY=1
RUN git clone https://github.com/sdhash/sdhash.git && cd sdhash && make && make install && cd .. && rm -rf sdhash/

RUN git clone git://github.com/trendmicro/tlsh.git && \
cd tlsh && \
git checkout master && \
./make.sh
