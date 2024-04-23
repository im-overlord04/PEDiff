# export DOCKER_BUILDKIT=1

FROM ubuntu:22.04

RUN apt update && apt install --no-install-recommends -y wget git automake libtool make cmake gcc g++ pkg-config libmagic-dev curl \
    tar unzip libglib2.0-0 libssl-dev libfuzzy-dev software-properties-common python3-software-properties build-essential python3.10 openssh-client

RUN apt install -y ssdeep

RUN wget --no-check-certificate https://github.com/protocolbuffers/protobuf/releases/download/v2.5.0/protobuf-2.5.0.tar.gz && \
    tar -xzf protobuf-2.5.0.tar.gz && rm protobuf-2.5.0.tar.gz && \
    cd protobuf-2.5.0 && ./configure && make && make install && ldconfig && cd .. && rm -rf protobuf-2.5.0/ 

# sdhash
# ARG GIT_SSL_NO_VERIFY=0
RUN git clone https://github.com/sdhash/sdhash.git && cd sdhash && make && make install && cd .. && rm -rf sdhash/

RUN git clone https://github.com/trendmicro/tlsh.git && \
cd tlsh && \
git checkout master && \
./make.sh && \
cd .. && rm -rf tlsh

# bitshred

RUN mkdir ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts
RUN --mount=type=ssh git clone git@github.com:im-overlord04/bitshred-python.git ~/bitshred

# mrsh-v2

RUN wget https://www.fbreitinger.de/wp-content/uploads/2018/07/mrsh_v2.0.zip && unzip mrsh_v2.0.zip && cd mrsh_v2.0 &&\
    make && cp mrsh /usr/bin && cd .. rm -rf mrsh_v2.0 && rm mrsh_v2.0.zip

# pefile
RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3.10

RUN pip install pefile && wget -O /usr/local/lib/python3.10/dist-packages/pefile.py https://raw.githubusercontent.com/erocarrera/pefile/master/pefile.py
    